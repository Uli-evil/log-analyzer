"""
loader.py — Pipeline ETL: Carga a SQLite
=========================================
Toma el DataFrame unificado del transformer y lo persiste
en una base de datos SQLite local.

Tablas creadas automáticamente:
    events           — todos los eventos normalizados
    anomalies        — eventos marcados como anomalía por el detector
    detection_rules  — reglas SQL configurables para detección basada en reglas
    run_log          — historial de ejecuciones del pipeline

Uso:
    from core.loader import Loader

    loader = Loader("data/log_analyzer.db")
    loader.init_db()
    loader.insert_events(df_unified)
    df = loader.query_events(severity_min=3)
"""

import json
import sqlite3
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# SCHEMA SQL
# ---------------------------------------------------------------------------
SCHEMA_SQL = """
-- Tabla principal de eventos normalizados
CREATE TABLE IF NOT EXISTS events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT,
    source           TEXT,          -- linux | network | windows
    event_type       TEXT,
    raw_event_type   TEXT,
    src_ip           TEXT,
    dst_ip           TEXT,
    src_port         INTEGER,
    dst_port         INTEGER,
    user             TEXT,
    severity         INTEGER,       -- 1=info … 5=critical
    is_anomaly_hint  INTEGER,       -- 0 | 1
    hour_of_day      INTEGER,
    is_night         INTEGER,       -- 0 | 1
    is_weekend       INTEGER,       -- 0 | 1
    failed_last_5min INTEGER,
    bytes_total      INTEGER,
    duration_sec     REAL,
    extra            TEXT,
    inserted_at      TEXT DEFAULT (datetime('now'))
);

-- Índices para queries frecuentes
CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_src_ip     ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_severity   ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_source     ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);

-- Anomalías detectadas por el modelo ML
CREATE TABLE IF NOT EXISTS anomalies (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id      INTEGER REFERENCES events(id),
    method        TEXT,             -- isolation_forest | sql_rule | combined
    score         REAL,             -- score del modelo (más negativo = más anómalo)
    rule_name     TEXT,             -- nombre de la regla SQL si aplica
    summary         TEXT,             -- análisis del motor de seguridad
    severity      TEXT,             -- crítica | alta | media | baja
    attack_pattern    TEXT,             -- patrón de ataque identificado
    response_action    TEXT,             -- acción de respuesta recomendada
    detected_at   TEXT DEFAULT (datetime('now'))
);

-- Reglas de detección basadas en lógica SQL (complementan el ML)
CREATE TABLE IF NOT EXISTS detection_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT UNIQUE,
    description TEXT,
    query       TEXT,               -- query SQL que retorna event IDs sospechosos
    severity    INTEGER,
    active      INTEGER DEFAULT 1,
    created_at  TEXT DEFAULT (datetime('now'))
);

-- Historial de ejecuciones del pipeline
CREATE TABLE IF NOT EXISTS run_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TEXT,
    finished_at  TEXT,
    source       TEXT,
    events_total INTEGER,
    anomalies_found INTEGER,
    status       TEXT,              -- success | error
    message      TEXT
);
"""

# ---------------------------------------------------------------------------
# REGLAS SQL PREDEFINIDAS
# ---------------------------------------------------------------------------
DEFAULT_RULES = [
    {
        "name":        "brute_force_ssh",
        "description": "IP con 5+ fallos de auth en los últimos 5 minutos",
        "query": """
            SELECT id FROM events
            WHERE event_type IN ('auth_failure', 'brute_force')
              AND failed_last_5min >= 5
              AND src_ip IS NOT NULL
        """,
        "severity": 4,
    },
    {
        "name":        "night_privilege_op",
        "description": "Operación de privilegio (sudo/su/runas) entre 22:00 y 06:00",
        "query": """
            SELECT id FROM events
            WHERE event_type = 'privilege_op'
              AND is_night = 1
        """,
        "severity": 4,
    },
    {
        "name":        "audit_log_cleared",
        "description": "Log de auditoría borrado — señal crítica de cobertura de huellas",
        "query": """
            SELECT id FROM events
            WHERE event_type = 'log_cleared'
        """,
        "severity": 5,
    },
    {
        "name":        "new_account_created",
        "description": "Cuenta de usuario creada — posible backdoor",
        "query": """
            SELECT id FROM events
            WHERE event_type = 'account_change'
              AND raw_event_type IN ('useradd', 'EventID_4720')
        """,
        "severity": 5,
    },
    {
        "name":        "c2_beacon",
        "description": "Tráfico de red tipo beacon C2 (larga duración, pocos bytes)",
        "query": """
            SELECT id FROM events
            WHERE event_type = 'c2_beacon'
        """,
        "severity": 5,
    },
    {
        "name":        "data_exfiltration",
        "description": "Flujo de red con alta ratio de upload (posible exfiltración)",
        "query": """
            SELECT id FROM events
            WHERE event_type = 'exfiltration'
        """,
        "severity": 5,
    },
    {
        "name":        "cross_source_ip",
        "description": "IP que aparece con severidad alta en múltiples fuentes",
        "query": """
            SELECT e.id FROM events e
            WHERE e.src_ip IN (
                SELECT src_ip FROM events
                WHERE severity >= 3 AND src_ip IS NOT NULL
                GROUP BY src_ip
                HAVING COUNT(DISTINCT source) > 1
            )
            AND e.severity >= 3
        """,
        "severity": 5,
    },
]


# ---------------------------------------------------------------------------
# CLASE LOADER
# ---------------------------------------------------------------------------

class Loader:

    def __init__(self, db_path: str = "data/log_analyzer.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        """Crea las tablas e inserta las reglas predefinidas."""
        with self._connect() as conn:
            conn.executescript(SCHEMA_SQL)

            for rule in DEFAULT_RULES:
                conn.execute("""
                    INSERT OR IGNORE INTO detection_rules
                        (name, description, query, severity)
                    VALUES (?, ?, ?, ?)
                """, (rule["name"], rule["description"],
                      rule["query"], rule["severity"]))

            conn.commit()
        print(f"✓ Base de datos inicializada: {self.db_path}")
        print(f"  Reglas cargadas: {len(DEFAULT_RULES)}")

    def insert_events(self, df: pd.DataFrame, batch_size: int = 500) -> int:
        """
        Inserta el DataFrame unificado en la tabla events.
        Usa INSERT OR IGNORE para evitar duplicados exactos.

        Retorna el número de filas insertadas.
        """
        if df.empty:
            print("  DataFrame vacío — nada que insertar.")
            return 0

        # Preparar columnas
        cols = [
            "timestamp", "source", "event_type", "raw_event_type",
            "src_ip", "dst_ip", "src_port", "dst_port", "user",
            "severity", "is_anomaly_hint", "hour_of_day",
            "is_night", "is_weekend", "failed_last_5min",
            "bytes_total", "duration_sec", "extra",
        ]

        insert_df = df[[c for c in cols if c in df.columns]].copy()

        # Convertir timestamp a string ISO
        if "timestamp" in insert_df.columns:
            insert_df["timestamp"] = insert_df["timestamp"].astype(str)

        # Convertir booleanos a int
        for col in ["is_anomaly_hint", "is_night", "is_weekend"]:
            if col in insert_df.columns:
                insert_df[col] = insert_df[col].fillna(0).astype(int)

        # Convertir columnas Int64 (nullable) a object con None para SQLite
        for col in insert_df.columns:
            if hasattr(insert_df[col], "dtype") and str(insert_df[col].dtype) == "Int64":
                insert_df[col] = insert_df[col].astype(object).where(
                    insert_df[col].notna(), other=None
                )

        # Insertar en lotes
        total = 0
        with self._connect() as conn:
            for start in range(0, len(insert_df), batch_size):
                batch = insert_df.iloc[start:start + batch_size]
                placeholders = ",".join(["?" * len(batch.columns)][0:1])
                placeholders = ",".join(["?"] * len(batch.columns))
                sql = f"""
                    INSERT INTO events ({",".join(batch.columns)})
                    VALUES ({placeholders})
                """
                conn.executemany(sql, batch.values.tolist())
                total += len(batch)
            conn.commit()

        print(f"✓ {total} eventos insertados en {self.db_path.name}")
        return total

    def insert_anomaly(self, event_id: int, method: str, score: float,
                       rule_name: Optional[str] = None,
                       summary: Optional[str] = None,
                       severity: Optional[str] = None,
                       attack_pattern: Optional[str] = None,
                       response_action: Optional[str] = None) -> int:
        """Inserta una anomalía detectada."""
        with self._connect() as conn:
            cursor = conn.execute("""
                INSERT INTO anomalies
                    (event_id, method, score, rule_name, summary,
                     risk_level, attack_pattern, response_action)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (event_id, method, score, rule_name, summary,
                  risk_level, attack_pattern, response_action))
            conn.commit()
            return cursor.lastrowid

    def run_detection_rules(self) -> pd.DataFrame:
        """
        Ejecuta todas las reglas SQL activas y retorna los eventos
        que disparan alguna regla.
        """
        results = []
        with self._connect() as conn:
            rules = conn.execute(
                "SELECT * FROM detection_rules WHERE active = 1"
            ).fetchall()

            for rule in rules:
                try:
                    ids = conn.execute(rule["query"]).fetchall()
                    for row in ids:
                        results.append({
                            "event_id":  row[0],
                            "rule_name": rule["name"],
                            "severity":  rule["severity"],
                        })
                except Exception as e:
                    print(f"  Error en regla '{rule['name']}': {e}")

        if not results:
            return pd.DataFrame(columns=["event_id", "rule_name", "severity"])

        return pd.DataFrame(results).drop_duplicates(subset=["event_id"])

    def query_events(
        self,
        severity_min: int = 1,
        source: Optional[str] = None,
        event_type: Optional[str] = None,
        src_ip: Optional[str] = None,
        limit: int = 1000,
    ) -> pd.DataFrame:
        """Query flexible sobre la tabla events."""
        conditions = ["severity >= ?"]
        params: list = [severity_min]

        if source:
            conditions.append("source = ?")
            params.append(source)
        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if src_ip:
            conditions.append("src_ip = ?")
            params.append(src_ip)

        where = " AND ".join(conditions)
        sql = f"""
            SELECT * FROM events
            WHERE {where}
            ORDER BY timestamp DESC
            LIMIT ?
        """
        params.append(limit)

        with self._connect() as conn:
            return pd.read_sql_query(sql, conn, params=params)

    def stats(self) -> dict:
        """Estadísticas rápidas de la base de datos."""
        with self._connect() as conn:
            total   = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            by_src  = dict(conn.execute(
                "SELECT source, COUNT(*) FROM events GROUP BY source"
            ).fetchall())
            by_sev  = dict(conn.execute(
                "SELECT severity, COUNT(*) FROM events GROUP BY severity ORDER BY severity"
            ).fetchall())
            anomalies = conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
            critical  = conn.execute(
                "SELECT COUNT(*) FROM events WHERE severity = 5"
            ).fetchone()[0]

        return {
            "total_events":    total,
            "by_source":       by_src,
            "by_severity":     by_sev,
            "anomalies_found": anomalies,
            "critical_events": critical,
        }

    def log_run(self, source: str, events_total: int,
                anomalies_found: int, status: str, message: str = ""):
        """Registra una ejecución del pipeline."""
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO run_log
                    (started_at, finished_at, source, events_total,
                     anomalies_found, status, message)
                VALUES (datetime('now'), datetime('now'), ?, ?, ?, ?, ?)
            """, (source, events_total, anomalies_found, status, message))
            conn.commit()


# ---------------------------------------------------------------------------
# EJECUCIÓN DIRECTA
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    import json
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from core.parser      import parse_file
    from core.transformer import transform_linux, transform_network, transform_windows, unify

    print("\n" + "="*55)
    print("  loader.py — Carga ETL a SQLite")
    print("="*55)

    # Inicializar DB
    loader = Loader("data/log_analyzer.db")
    loader.init_db()

    # Transformar
    print("\n[ETL] Transformando fuentes...")
    df_linux = transform_linux(parse_file("data/raw/sample_auth.log"))
    df_net   = transform_network(pd.read_csv("data/raw/network_traffic.csv"))
    df_win   = transform_windows(pd.read_csv("data/raw/windows_events.csv"))
    df_all   = unify([df_linux, df_net, df_win])

    # Cargar
    print("\n[SQL] Insertando en SQLite...")
    n = loader.insert_events(df_all)

    # Correr reglas
    print("\n[RULES] Ejecutando reglas de detección SQL...")
    rule_hits = loader.run_detection_rules()
    print(f"  Eventos que disparan reglas: {len(rule_hits)}")
    if not rule_hits.empty:
        print(rule_hits["rule_name"].value_counts().to_string())

    # Estadísticas
    print("\n--- Estadísticas de la DB ---")
    print(json.dumps(loader.stats(), indent=2))

    # Query de ejemplo
    print("\n--- Eventos críticos (severity=5) ---")
    critical = loader.query_events(severity_min=5, limit=10)
    if critical.empty:
        print("  Ninguno.")
    else:
        print(critical[["timestamp","source","event_type","src_ip","user","extra"]].to_string(index=False))

    print("\n✓ Siguiente paso: core/detector.py → Isolation Forest")
