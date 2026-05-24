"""
ai_engine.py — Motor de Análisis de Seguridad
==============================================
Capa de abstracción del motor de análisis inteligente.
El resto del proyecto no conoce el proveedor subyacente.

Uso:
    from core.ai_engine import SecurityAnalyst, AnalysisEngine, run_analysis_batch
"""

import os, sys, json, time, sqlite3, argparse
import pandas as pd
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except ImportError:
    pass

try:
    import anthropic as _provider
    _ENGINE_READY = True
except ImportError:
    _ENGINE_READY = False

_ENGINE_KEY   = os.getenv("AI_ENGINE_KEY", "")
_ENGINE_MODEL = "claude-sonnet-4-20250514"

_SYSTEM_PROMPT = """Eres un analista de ciberseguridad senior en un SOC.
Analiza el evento de seguridad y responde SOLO con JSON puro, sin markdown.

Claves requeridas:
{
  "summary": "qué ocurrió y por qué es sospechoso (2-3 oraciones en español)",
  "risk_level": "crítico | alto | medio | bajo",
  "attack_pattern": "patrón técnico en inglés (brute_force, c2_beacon, data_exfiltration, etc.)",
  "response_action": "acción inmediata concreta (1-2 oraciones en español)"
}"""

def _build_prompt(event: dict, anomaly: dict) -> str:
    method = anomaly.get("method","unknown")
    score  = anomaly.get("score", 0)
    rule   = anomaly.get("rule_name","")
    pat    = anomaly.get("likely_attack","")
    return f"""EVENTO DE SEGURIDAD PARA ANÁLISIS
Método de detección : {method}
{"Score de anomalía   : " + str(round(score,3)) if method=="isolation_forest" else ""}
{"Regla activada      : " + rule if rule else ""}
{"Patrón sugerido     : " + pat if pat else ""}

Fuente       : {event.get("source","N/A")}
Tipo evento  : {event.get("event_type","N/A")}
IP origen    : {event.get("src_ip","N/A")}
Usuario      : {event.get("user","N/A")}
Severidad    : {event.get("severity","N/A")} / 5
Hora         : {event.get("hour_of_day","N/A")}:00 {"(NOCTURNO)" if event.get("is_night") else ""}
Fallos 5 min : {event.get("failed_last_5min",0)}
Bytes totales: {event.get("bytes_total",0):,}
Contexto     : {event.get("extra","N/A")}

Responde con el JSON de análisis."""

def _local_analysis(event: dict, anomaly: dict) -> dict:
    ip   = event.get("src_ip","IP desconocida")
    user = event.get("user","usuario desconocido")
    pat  = anomaly.get("likely_attack","anomalous_behavior")
    fails= int(event.get("failed_last_5min",0))

    summaries = {
        "brute_force":              f"La IP {ip} realizó {fails} intentos fallidos de autenticación en menos de 5 minutos contra '{user}'. Patrón consistente con ataque de fuerza bruta automatizado.",
        "log_tampering":            f"Se detectó el borrado del registro de auditoría ejecutado por '{user}'. Acción característica de un atacante que elimina evidencia de actividad maliciosa.",
        "data_exfiltration":        f"Flujo de red con ratio de upload superior al 85% desde {ip}. Indica posible extracción no autorizada de información del sistema.",
        "c2_beacon":                f"Tráfico periódico de baja intensidad hacia {ip}. Duración prolongada y mínimo volumen de datos son consistentes con señalización de comando y control.",
        "privilege_escalation_night": f"El usuario '{user}' ejecutó operaciones con privilegios elevados a las {event.get('hour_of_day','?')}:00. Actividad nocturna con escalada es estadísticamente anómala.",
        "multi_vector_attack":      f"La IP {ip} aparece en eventos de Linux, Windows y tráfico de red simultáneamente. Indica ataque coordinado en múltiples vectores.",
        "persistence_backdoor":     f"Creación de cuenta de usuario no autorizada por '{user}'. Indicador de intento de persistencia en el sistema.",
        "reconnaissance":           f"La IP {ip} realizó conexiones a múltiples puertos con mínima transferencia. Patrón típico de escaneo de reconocimiento.",
    }
    actions = {
        "brute_force":              f"Bloquear {ip} en el firewall. Verificar si '{user}' fue comprometido y forzar cambio de credenciales.",
        "log_tampering":            "Aislar el sistema de la red. Iniciar análisis forense y revisar cambios en las últimas 24 horas.",
        "data_exfiltration":        f"Bloquear tráfico saliente hacia {ip}. Identificar y catalogar los datos transferidos.",
        "c2_beacon":                f"Bloquear {ip} en todos los controles de red. Escanear el endpoint en busca de malware.",
        "privilege_escalation_night": f"Verificar autorización de '{user}'. Revisar comandos ejecutados y considerar revocar credenciales.",
        "multi_vector_attack":      f"Activar protocolo de respuesta a incidentes P1. Aislar sistemas afectados y bloquear {ip}.",
        "persistence_backdoor":     "Deshabilitar la cuenta creada de inmediato. Auditar cambios de cuentas en las últimas 48 horas.",
        "reconnaissance":           f"Bloquear {ip} en el perímetro. Revisar servicios detectados y reducir superficie de exposición.",
    }
    risk_map = {
        "brute_force":"alto","log_tampering":"crítico","data_exfiltration":"crítico",
        "c2_beacon":"crítico","privilege_escalation_night":"alto",
        "multi_vector_attack":"crítico","persistence_backdoor":"crítico","reconnaissance":"medio",
    }
    return {
        "summary":         summaries.get(pat, f"Evento '{event.get('event_type','')}' desde {ip} con características estadísticamente anómalas."),
        "risk_level":      risk_map.get(pat,"medio"),
        "attack_pattern":  pat,
        "response_action": actions.get(pat, f"Investigar el evento y revisar logs adicionales relacionados con {ip}."),
    }


class SecurityAnalyst:
    """Analista de seguridad basado en IA. El proveedor es opaco para el exterior."""

    def __init__(self):
        self._engine = None
        self._ready  = False
        key = _ENGINE_KEY
        if not key or "tu-clave" in key:
            print("⚠  Motor de análisis: configura AI_ENGINE_KEY en .env")
            print("   Usando análisis local como respaldo.")
            return
        if not _ENGINE_READY:
            print("⚠  Motor de análisis: ejecuta pip install anthropic")
            print("   Usando análisis local como respaldo.")
            return
        try:
            self._engine = _provider.Anthropic(api_key=key)
            self._ready  = True
            print("✓  Motor de análisis conectado")
        except Exception as e:
            print(f"⚠  Error al inicializar el motor: {e}")

    @property
    def mode(self) -> str:
        return "online" if self._ready else "local"

    def analyze(self, event: dict, anomaly: dict) -> Optional[dict]:
        """Analiza un evento y retorna diagnóstico estructurado."""
        if not self._ready:
            return _local_analysis(event, anomaly)
        try:
            resp = self._engine.messages.create(
                model=_ENGINE_MODEL, max_tokens=512,
                system=_SYSTEM_PROMPT,
                messages=[{"role":"user","content":_build_prompt(event,anomaly)}],
            )
            raw = resp.content[0].text.strip().replace("```json","").replace("```","").strip()
            r   = json.loads(raw)
            return {
                "summary":         r.get("summary") or r.get("explanation",""),
                "risk_level":      r.get("risk_level") or r.get("severity","medio"),
                "attack_pattern":  r.get("attack_pattern") or r.get("likely_attack",""),
                "response_action": r.get("response_action") or r.get("recommended_action",""),
            }
        except Exception:
            return _local_analysis(event, anomaly)


class AnalysisEngine:
    """Orquesta el análisis en lote sobre la base de datos."""

    def __init__(self, db_path: str = "data/log_analyzer.db"):
        self.db_path = Path(db_path)
        self.analyst = SecurityAnalyst()

    def _connect(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _load_pending(self, limit: int) -> list:
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT a.id as anomaly_id, a.event_id, a.method,
                       a.score, a.rule_name, a.likely_attack,
                       a.severity as anomaly_severity, e.*
                FROM anomalies a JOIN events e ON e.id = a.event_id
                WHERE a.summary IS NULL
                ORDER BY a.score ASC, e.severity DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def _save(self, anomaly_id: int, result: dict):
        with self._connect() as conn:
            conn.execute("""
                UPDATE anomalies SET
                    summary=?, risk_level=?, attack_pattern=?, response_action=?
                WHERE id=?
            """, (result.get("summary"), result.get("risk_level"),
                  result.get("attack_pattern"), result.get("response_action"),
                  anomaly_id))
            conn.commit()

    def run(self, limit: int = 10, delay: float = 0.5) -> int:
        pending = self._load_pending(limit)
        if not pending:
            print("✓ Todos los eventos ya tienen análisis completado.")
            return 0
        print(f"\n  Analizando {len(pending)} eventos [modo: {self.analyst.mode}]\n")
        done = 0
        for i, row in enumerate(pending, 1):
            print(f"  [{i}/{len(pending)}] #{row['event_id']} — {row['event_type']} — {row.get('src_ip','sin IP')}")
            result = self.analyst.analyze(event=row, anomaly=row)
            if result:
                self._save(row["anomaly_id"], result)
                print(f"         ✓ {result['risk_level'].upper()}: {result['attack_pattern']}")
                print(f"           {result['summary'][:80]}...")
                done += 1
            else:
                print(f"         ✗ No se pudo analizar")
            if self.analyst._ready and i < len(pending):
                time.sleep(delay)
        print(f"\n  ✓ {done}/{len(pending)} análisis completados")
        return done

    def get_results(self, limit: int = 100) -> pd.DataFrame:
        with self._connect() as conn:
            return pd.read_sql_query("""
                SELECT a.id, a.method, a.score, a.rule_name,
                       a.summary, a.risk_level, a.attack_pattern,
                       a.response_action, a.detected_at,
                       e.timestamp, e.source, e.event_type,
                       e.src_ip, e.user, e.severity, e.bytes_total, e.extra
                FROM anomalies a JOIN events e ON e.id = a.event_id
                WHERE a.summary IS NOT NULL
                ORDER BY e.severity DESC, a.score ASC LIMIT ?
            """, conn, params=(limit,))

    def stats(self) -> dict:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
            done  = conn.execute("SELECT COUNT(*) FROM anomalies WHERE summary IS NOT NULL").fetchone()[0]
            by_risk = dict(conn.execute("SELECT risk_level, COUNT(*) FROM anomalies WHERE risk_level IS NOT NULL GROUP BY risk_level").fetchall())
            by_pat  = dict(conn.execute("SELECT attack_pattern, COUNT(*) FROM anomalies WHERE attack_pattern IS NOT NULL GROUP BY attack_pattern ORDER BY COUNT(*) DESC").fetchall())
        return {"total":total,"analyzed":done,"pending":total-done,"by_risk":by_risk,"by_pattern":by_pat}


def run_analysis_batch(db_path: str, limit: int = 10):
    """Punto de entrada público para otros módulos."""
    return AnalysisEngine(db_path=db_path).run(limit=limit)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Motor de análisis — Log Analyzer")
    ap.add_argument("--db",      default="data/log_analyzer.db")
    ap.add_argument("--limit",   type=int, default=10)
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--delay",   type=float, default=0.5)
    args = ap.parse_args()
    db_path = ROOT / args.db
    if not db_path.exists():
        print(f"ERROR: {db_path} no existe. Ejecuta: python run_etl.py && python core/detector.py")
        sys.exit(1)
    print(f"\n{'='*55}\n  Log Analyzer — Motor de Análisis\n{'='*55}")
    engine = AnalysisEngine(db_path=str(db_path))
    if args.summary:
        s = engine.stats()
        print(f"\n  Total: {s['total']:,}  Analizados: {s['analyzed']:,}  Pendientes: {s['pending']:,}")
        for level, n in s["by_risk"].items(): print(f"    {level:<12} {n:>5}")
        sys.exit(0)
    n = engine.run(limit=args.limit, delay=args.delay)
    s = engine.stats()
    print(f"\n{'='*55}\n  Analizados: {s['analyzed']:,}/{s['total']:,}\n  Siguiente: streamlit run app.py\n{'='*55}\n")
