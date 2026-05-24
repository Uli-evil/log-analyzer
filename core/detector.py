"""
detector.py — Detección de Anomalías
======================================
Combina dos enfoques complementarios:

  1. Reglas SQL  — detecta ataques CONOCIDOS (brute force, log borrado, etc.)
                   Determinista, explicable, sin ML.

  2. Isolation Forest — detecta comportamiento ESTADÍSTICAMENTE ANORMAL
                        No necesita reglas predefinidas.
                        Captura lo que las reglas no cubren.

Flujo:
    BD (events) → features numéricos → Isolation Forest → anomalies
    BD (events) → reglas SQL         → anomalies

Uso:
    python core/detector.py
    python core/detector.py --source linux
    python core/detector.py --contamination 0.08
    python core/detector.py --explain   (llama a Claude API por cada anomalía)
"""

import sys
import json
import argparse
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Optional

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from core.loader import Loader

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_OK = True
except ImportError:
    SKLEARN_OK = False
    print("⚠ scikit-learn no instalado. Ejecuta: pip install scikit-learn")


# ---------------------------------------------------------------------------
# FEATURES PARA EL MODELO
# Estas 6 columnas son las que Isolation Forest usará para aprender
# qué es "normal" y qué es "anómalo"
# ---------------------------------------------------------------------------
FEATURE_COLS = [
    "hour_of_day",       # ¿A qué hora ocurrió? (ataques tienden a ser nocturnos)
    "is_night",          # ¿Entre 22:00 y 06:00?
    "is_weekend",        # ¿Fin de semana?
    "failed_last_5min",  # ¿Cuántos fallos recientes de esta IP?
    "severity",          # Severidad asignada por el transformer
    "bytes_total",       # Bytes transferidos (detecta exfiltración)
]

# Mapeo de score de Isolation Forest → etiqueta legible
# El score va de -1 (muy anómalo) a +0.5 (muy normal)
def score_to_label(score: float) -> str:
    if score < -0.3:   return "crítica"
    if score < -0.15:  return "alta"
    if score < -0.05:  return "media"
    return "baja"


# ---------------------------------------------------------------------------
# CLASE DETECTOR
# ---------------------------------------------------------------------------

class AnomalyDetector:

    def __init__(
        self,
        db_path: str = "data/log_analyzer.db",
        contamination: float = 0.05,
        random_state: int = 42,
    ):
        """
        Parámetros
        ----------
        db_path       : ruta a la base de datos SQLite
        contamination : fracción esperada de anomalías (0.01 a 0.5)
                        0.05 = esperamos que el 5% de los eventos sean anómalos
        random_state  : semilla para reproducibilidad
        """
        self.loader       = Loader(db_path)
        self.contamination = contamination
        self.random_state  = random_state
        self.model         = None
        self.scaler        = None

    # ── 1. Cargar eventos desde la BD ──────────────────────────────────────

    def load_events(self, source: Optional[str] = None) -> pd.DataFrame:
        """
        Carga eventos de la BD.
        Si source='linux'|'network'|'windows', filtra por fuente.
        """
        df = self.loader.query_events(
            severity_min=1,
            source=source,
            limit=100_000,
        )
        print(f"  Eventos cargados: {len(df):,}"
              + (f" (fuente: {source})" if source else " (todas las fuentes)"))
        return df

    # ── 2. Preparar features ───────────────────────────────────────────────

    def prepare_features(self, df: pd.DataFrame) -> np.ndarray:
        """
        Extrae y escala las columnas numéricas para el modelo.
        Retorna una matriz numpy lista para fit/predict.
        """
        available = [c for c in FEATURE_COLS if c in df.columns]
        X = df[available].copy()

        # Rellenar nulos con 0 (eventos sin IP no tienen failed_last_5min)
        X = X.fillna(0)

        # Escalar: Isolation Forest es sensible a la escala de las features
        # bytes_total puede ser millones mientras hour_of_day es 0-23
        if self.scaler is None:
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
        else:
            X_scaled = self.scaler.transform(X)

        return X_scaled, available

    # ── 3. Entrenar y predecir con Isolation Forest ────────────────────────

    def detect_ml(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Aplica Isolation Forest sobre los eventos.

        Cómo funciona Isolation Forest:
        - Construye árboles de decisión aleatorios
        - Los eventos ANÓMALOS son más fáciles de aislar (caminos más cortos)
        - Score: negativo = anómalo, positivo = normal
        - contamination=0.05 → marca el 5% más anómalo

        Retorna df con columnas 'if_score' e 'if_anomaly' agregadas.
        """
        if not SKLEARN_OK:
            df["if_score"]   = 0.0
            df["if_anomaly"] = False
            return df

        print(f"\n  Entrenando Isolation Forest...")
        print(f"    contamination = {self.contamination}")
        print(f"    features      = {FEATURE_COLS}")
        print(f"    muestras      = {len(df):,}")

        X_scaled, used_cols = self.prepare_features(df)

        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=200,       # más árboles = más estable
            max_samples="auto",
            random_state=self.random_state,
            n_jobs=-1,              # usar todos los cores disponibles
        )

        # fit_predict: -1 = anómalo, 1 = normal
        predictions = self.model.fit_predict(X_scaled)
        scores      = self.model.score_samples(X_scaled)

        df = df.copy()
        df["if_score"]   = scores
        df["if_anomaly"] = predictions == -1

        n_anomalies = df["if_anomaly"].sum()
        print(f"    ✓ Anomalías detectadas: {n_anomalies:,} "
              f"({100*n_anomalies/len(df):.1f}% del total)")

        return df

    # ── 4. Ejecutar reglas SQL ─────────────────────────────────────────────

    def detect_rules(self) -> pd.DataFrame:
        """
        Ejecuta las 7 reglas SQL predefinidas en detection_rules.
        Retorna DataFrame con event_id, rule_name, severity.
        """
        print(f"\n  Ejecutando reglas SQL...")
        hits = self.loader.run_detection_rules()
        print(f"    ✓ Eventos detectados por reglas: {len(hits):,}")
        if not hits.empty:
            counts = hits["rule_name"].value_counts()
            for rule, count in counts.items():
                print(f"      {rule:<30} {count:>5}")
        return hits

    # ── 5. Combinar y persistir resultados ────────────────────────────────

    def save_anomalies(
        self,
        df_with_scores: pd.DataFrame,
        rule_hits: pd.DataFrame,
    ) -> int:
        """
        Guarda las anomalías detectadas en la tabla 'anomalies'.
        Combina resultados de ML y reglas SQL.
        Retorna el número de anomalías guardadas.
        """
        saved = 0

        # Anomalías del Isolation Forest
        if "if_anomaly" in df_with_scores.columns:
            ml_anomalies = df_with_scores[df_with_scores["if_anomaly"]]
            for _, row in ml_anomalies.iterrows():
                score      = float(row.get("if_score", 0))
                sev_label  = score_to_label(score)
                self.loader.insert_anomaly(
                    event_id   = int(row["id"]),
                    method     = "isolation_forest",
                    score      = score,
                    severity   = sev_label,
                    likely_attack = _infer_attack(row),
                )
                saved += 1

        # Anomalías de reglas SQL
        if not rule_hits.empty:
            for _, row in rule_hits.iterrows():
                self.loader.insert_anomaly(
                    event_id  = int(row["event_id"]),
                    method    = "sql_rule",
                    score     = -1.0,   # reglas son deterministas
                    rule_name = row["rule_name"],
                    severity  = _severity_int_to_label(int(row["severity"])),
                    likely_attack = _rule_to_attack(row["rule_name"]),
                )
                saved += 1

        print(f"\n  ✓ {saved:,} anomalías guardadas en tabla 'anomalies'")
        return saved

    # ── 6. Reporte de resultados ───────────────────────────────────────────

    def report(self, df_with_scores: pd.DataFrame, rule_hits: pd.DataFrame):
        """Imprime un resumen de los resultados de detección."""

        print(f"\n{'='*55}")
        print("  REPORTE DE DETECCIÓN DE ANOMALÍAS")
        print(f"{'='*55}")

        # ML
        if "if_anomaly" in df_with_scores.columns:
            ml = df_with_scores[df_with_scores["if_anomaly"]]
            print(f"\n  Isolation Forest ({len(ml)} anomalías):")

            if not ml.empty:
                print(f"\n  Por fuente:")
                for src, grp in ml.groupby("source"):
                    print(f"    {src:<12} {len(grp):>5} eventos")

                print(f"\n  Por tipo de evento:")
                for et, grp in ml.groupby("event_type"):
                    print(f"    {et:<25} {len(grp):>5}")

                print(f"\n  Top 5 IPs más anómalas:")
                top_ips = (
                    ml[ml["src_ip"].notna()]
                    .nsmallest(20, "if_score")
                    .groupby("src_ip")["if_score"]
                    .mean()
                    .nsmallest(5)
                )
                for ip, score in top_ips.items():
                    print(f"    {ip:<20} score={score:.3f}")

        # Reglas SQL
        if not rule_hits.empty:
            print(f"\n  Reglas SQL ({len(rule_hits)} eventos):")
            for rule, count in rule_hits["rule_name"].value_counts().items():
                sev = rule_hits[rule_hits["rule_name"]==rule]["severity"].iloc[0]
                sev_str = "⚠ CRÍTICO" if sev == 5 else "⬆ ALTO" if sev == 4 else ""
                print(f"    {rule:<30} {count:>5}  {sev_str}")

        # Score más bajos (más anómalos)
        if "if_score" in df_with_scores.columns:
            print(f"\n  Top 10 eventos más anómalos (score más negativo):")
            top10 = df_with_scores.nsmallest(10, "if_score")[
                ["id", "timestamp", "source", "event_type",
                 "src_ip", "user", "severity", "if_score"]
            ]
            for _, r in top10.iterrows():
                print(f"    [{r['source']:<8}] {r['event_type']:<22} "
                      f"IP={str(r['src_ip']):<18} "
                      f"score={r['if_score']:.3f}")

        print(f"\n{'='*55}")
        print("  Siguiente paso: core/claude_client.py")
        print("  → Explicar cada anomalía con Claude API")
        print(f"{'='*55}\n")


# ---------------------------------------------------------------------------
# FUNCIONES AUXILIARES
# ---------------------------------------------------------------------------

def _infer_attack(row) -> str:
    """Infiere el tipo de ataque probable a partir del evento."""
    et  = str(row.get("event_type", ""))
    sev = int(row.get("severity", 1))
    fl  = int(row.get("failed_last_5min", 0))
    night = int(row.get("is_night", 0))

    if fl >= 5:                     return "brute_force"
    if et == "c2_beacon":           return "botnet_c2"
    if et == "exfiltration":        return "data_exfiltration"
    if et == "log_cleared":         return "log_tampering"
    if et == "account_change":      return "persistence_backdoor"
    if et == "privilege_op" and night: return "privilege_escalation_night"
    if et == "auth_failure":        return "credential_attack"
    if et == "recon":               return "reconnaissance"
    if sev >= 4:                    return "high_severity_event"
    return "anomalous_behavior"


def _rule_to_attack(rule_name: str) -> str:
    MAP = {
        "brute_force_ssh":       "brute_force",
        "night_privilege_op":    "privilege_escalation_night",
        "audit_log_cleared":     "log_tampering",
        "new_account_created":   "persistence_backdoor",
        "c2_beacon":             "botnet_c2",
        "data_exfiltration":     "data_exfiltration",
        "cross_source_ip":       "multi_vector_attack",
    }
    return MAP.get(rule_name, "unknown")


def _severity_int_to_label(sev: int) -> str:
    return {5: "crítica", 4: "alta", 3: "media", 2: "baja"}.get(sev, "baja")


# ---------------------------------------------------------------------------
# EJECUCIÓN DIRECTA
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Detector de anomalías — Log Analyzer")
    ap.add_argument("--db", default="data/log_analyzer.db",
                    help="Ruta a la base de datos SQLite")
    ap.add_argument("--source", default=None,
                    choices=["linux", "network", "windows"],
                    help="Filtrar por fuente (default: todas)")
    ap.add_argument("--contamination", type=float, default=0.05,
                    help="Fracción esperada de anomalías (default: 0.05)")
    ap.add_argument("--explain", action="store_true",
                    help="Llamar a Claude API para explicar anomalías")
    args = ap.parse_args()

    db_path = ROOT / args.db
    if not db_path.exists():
        print(f"ERROR: No existe {db_path}")
        print("Ejecuta primero: python run_etl.py")
        sys.exit(1)

    print(f"\n{'='*55}")
    print("  Log Analyzer — Detector de Anomalías")
    print(f"{'='*55}")
    print(f"  DB            : {db_path}")
    print(f"  Contamination : {args.contamination}")
    print(f"  Fuente        : {args.source or 'todas'}")

    detector = AnomalyDetector(
        db_path=str(db_path),
        contamination=args.contamination,
    )

    # ── Paso 1: Cargar eventos ─────────────────────────────────────────────
    print(f"\n[1/4] Cargando eventos de la BD...")
    df = detector.load_events(source=args.source)

    if df.empty:
        print("  No hay eventos. Ejecuta python run_etl.py primero.")
        sys.exit(1)

    # ── Paso 2: Isolation Forest ───────────────────────────────────────────
    print(f"\n[2/4] Detección ML — Isolation Forest...")
    df = detector.detect_ml(df)

    # ── Paso 3: Reglas SQL ─────────────────────────────────────────────────
    print(f"\n[3/4] Detección por reglas SQL...")
    rule_hits = detector.detect_rules()

    # ── Paso 4: Guardar y reportar ─────────────────────────────────────────
    print(f"\n[4/4] Guardando resultados...")
    n_saved = detector.save_anomalies(df, rule_hits)

    # Reporte
    detector.report(df, rule_hits)

    # ── Opcional: explicar con Claude API ──────────────────────────────────
    if args.explain:
        print("  Llamando a Claude API para explicar anomalías...")
        try:
            from core.claude_client import explain_anomalies_batch
            explain_anomalies_batch(db_path=str(db_path), limit=10)
        except ImportError:
            print("  claude_client.py aún no existe — se crea en la siguiente etapa")
        except Exception as e:
            print(f"  Error al llamar Claude API: {e}")

    # Registrar ejecución
    detector.loader.log_run(
        source=args.source or "all",
        events_total=len(df),
        anomalies_found=n_saved,
        status="success",
    )

    print(f"  ✓ Proceso completado. {n_saved:,} anomalías en la BD.")
    print(f"\n  Para ver las anomalías en DB Browser:")
    print(f"    SELECT * FROM anomalies ORDER BY detected_at DESC;")
    print(f"\n  Siguiente paso:")
    print(f"    python core/claude_client.py  → explicar con IA\n")


if __name__ == "__main__":
    main()
