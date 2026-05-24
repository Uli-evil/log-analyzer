"""
claude_client.py — Integración con Claude API
===============================================
Toma anomalías detectadas por el detector y genera explicaciones
en lenguaje natural usando Claude API.

Para cada anomalía produce:
  - explanation    : qué pasó y por qué es sospechoso
  - severity       : crítica / alta / media / baja
  - likely_attack  : tipo de ataque probable
  - recommended_action : acción concreta inmediata

Uso:
    python core/claude_client.py
    python core/claude_client.py --limit 5
    python core/claude_client.py --event-id 42
"""

import os
import sys
import json
import time
import argparse
import sqlite3
import pandas as pd
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# Cargar variables de entorno desde .env
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except ImportError:
    pass

try:
    import anthropic
    ANTHROPIC_OK = True
except ImportError:
    ANTHROPIC_OK = False


# ---------------------------------------------------------------------------
# PROMPTS
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """Eres un analista de ciberseguridad senior en un SOC (Security Operations Center).
Recibirás datos de un evento de seguridad que fue marcado como anomalía por un sistema de detección.

Tu tarea es analizar el evento y responder ÚNICAMENTE con un objeto JSON válido.
No incluyas explicaciones fuera del JSON. No uses markdown. Solo JSON puro.

El JSON debe tener exactamente estas 4 claves:
{
  "explanation": "Explicación clara en español de qué ocurrió y por qué es sospechoso (2-3 oraciones)",
  "severity": "crítica | alta | media | baja",
  "likely_attack": "nombre técnico del ataque probable en inglés (ej: brute_force, lateral_movement, data_exfiltration, privilege_escalation, c2_beacon, log_tampering, reconnaissance, credential_stuffing)",
  "recommended_action": "Acción concreta e inmediata que debe tomar el analista (1-2 oraciones)"
}"""


def build_user_prompt(event: dict, anomaly: dict) -> str:
    """Construye el prompt con contexto del evento y la anomalía."""

    method      = anomaly.get("method", "unknown")
    score       = anomaly.get("score", 0)
    rule_name   = anomaly.get("rule_name", "")
    likely      = anomaly.get("likely_attack", "")

    prompt = f"""EVENTO DE SEGURIDAD DETECTADO COMO ANOMALÍA

Método de detección: {method}
{"Score de anomalía: " + str(round(score, 3)) + " (más negativo = más anómalo)" if method == "isolation_forest" else ""}
{"Regla que disparó: " + rule_name if rule_name else ""}
{"Tipo de ataque sugerido por el sistema: " + likely if likely else ""}

DATOS DEL EVENTO:
- Timestamp     : {event.get("timestamp", "N/A")}
- Fuente        : {event.get("source", "N/A")} (linux / windows / network)
- Tipo evento   : {event.get("event_type", "N/A")}
- Tipo original : {event.get("raw_event_type", "N/A")}
- IP origen     : {event.get("src_ip", "N/A")}
- IP destino    : {event.get("dst_ip", "N/A")}
- Puerto        : {event.get("src_port", "N/A")}
- Usuario       : {event.get("user", "N/A")}
- Severidad     : {event.get("severity", "N/A")} / 5
- Hora del día  : {event.get("hour_of_day", "N/A")}:00
- ¿Nocturno?    : {"Sí" if event.get("is_night") else "No"}
- ¿Fin de semana?: {"Sí" if event.get("is_weekend") else "No"}
- Fallos IP (5min): {event.get("failed_last_5min", 0)}
- Bytes totales : {event.get("bytes_total", 0):,}
- Duración (seg): {event.get("duration_sec", 0)}
- Extra         : {event.get("extra", "N/A")}

Analiza este evento y responde con el JSON solicitado."""

    return prompt


# ---------------------------------------------------------------------------
# CLASE PRINCIPAL
# ---------------------------------------------------------------------------

class ClaudeSecurityClient:

    def __init__(self, db_path: str = "data/log_analyzer.db"):
        self.db_path = Path(db_path)
        self.api_key = os.getenv("ANTHROPIC_API_KEY", "")

        if not self.api_key or self.api_key == "sk-ant-tu-clave-aqui":
            print("⚠  ANTHROPIC_API_KEY no configurada.")
            print("   Edita el archivo .env y agrega tu clave.")
            print("   Obtenerla en: https://console.anthropic.com/")
            self.client = None
        elif not ANTHROPIC_OK:
            print("⚠  Librería anthropic no instalada.")
            print("   Ejecuta: pip install anthropic")
            self.client = None
        else:
            self.client = anthropic.Anthropic(api_key=self.api_key)
            print("✓  Claude API conectada")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def load_unexplained_anomalies(self, limit: int = 10) -> list[dict]:
        """Carga anomalías que aún no tienen explicación de Claude."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT a.id as anomaly_id, a.event_id, a.method,
                       a.score, a.rule_name, a.likely_attack,
                       a.severity as anomaly_severity,
                       e.*
                FROM anomalies a
                JOIN events e ON e.id = a.event_id
                WHERE a.explanation IS NULL
                  AND a.method != 'claude_explained'
                ORDER BY a.score ASC, e.severity DESC
                LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def explain_anomaly(self, event: dict, anomaly: dict) -> Optional[dict]:
        """
        Llama a Claude API para explicar una anomalía.
        Retorna dict con los 4 campos, o None si falla.
        """
        if not self.client:
            return self._mock_explanation(event, anomaly)

        prompt = build_user_prompt(event, anomaly)

        try:
            message = self.client.messages.create(
                model      = "claude-sonnet-4-20250514",
                max_tokens = 512,
                system     = SYSTEM_PROMPT,
                messages   = [{"role": "user", "content": prompt}],
            )

            raw = message.content[0].text.strip()

            # Limpiar posibles backticks de markdown
            raw = raw.replace("```json", "").replace("```", "").strip()

            result = json.loads(raw)

            # Validar que tiene las 4 claves
            required = ["explanation", "severity", "likely_attack", "recommended_action"]
            for key in required:
                if key not in result:
                    result[key] = "No disponible"

            return result

        except json.JSONDecodeError as e:
            print(f"    Error parseando JSON de Claude: {e}")
            print(f"    Respuesta cruda: {raw[:200]}")
            return None
        except Exception as e:
            print(f"    Error llamando Claude API: {e}")
            return None

    def _mock_explanation(self, event: dict, anomaly: dict) -> dict:
        """
        Genera una explicación simulada cuando no hay API key.
        Útil para probar el flujo sin gastar tokens.
        """
        et     = event.get("event_type", "unknown")
        ip     = event.get("src_ip", "IP desconocida")
        user   = event.get("user", "usuario desconocido")
        night  = event.get("is_night", 0)
        fails  = event.get("failed_last_5min", 0)
        rule   = anomaly.get("rule_name", "")

        explanations = {
            "brute_force":       f"La IP {ip} realizó {fails} intentos fallidos de autenticación en menos de 5 minutos, lo que indica un ataque de fuerza bruta automatizado contra la cuenta '{user}'.",
            "log_tampering":     f"Se detectó el borrado del log de auditoría (Event ID 1102) desde el usuario '{user}'. Esta acción es característica de un atacante que intenta cubrir sus huellas tras comprometer el sistema.",
            "data_exfiltration": f"Se detectó un flujo de red con ratio de upload extremadamente alto desde {ip}. El volumen de datos salientes supera significativamente el patrón normal, indicando posible exfiltración.",
            "c2_beacon":         f"Se identificó tráfico periódico de baja intensidad hacia {ip} con patrón de beacon. La duración prolongada y el bajo volumen de bytes son consistentes con comunicación de Command & Control.",
            "privilege_escalation_night": f"El usuario '{user}' ejecutó operaciones de privilegio elevado a las {event.get('hour_of_day','?')}:00 horas. La actividad nocturna con privilegios es estadísticamente anómala.",
            "multi_vector_attack": f"La IP {ip} aparece simultáneamente en eventos de Linux, Windows y tráfico de red con severidad alta. Este patrón sugiere un ataque coordinado en múltiples vectores.",
        }

        attack  = anomaly.get("likely_attack", "anomalous_behavior")
        expl    = explanations.get(attack, f"El evento de tipo '{et}' desde {ip} presenta características estadísticamente anómalas respecto al comportamiento base del sistema.")

        actions = {
            "brute_force":              f"Bloquear inmediatamente la IP {ip} en el firewall. Revisar si la cuenta '{user}' fue comprometida. Habilitar autenticación de dos factores.",
            "log_tampering":            f"Aislar el sistema {event.get('computer', 'afectado')} de la red. Iniciar análisis forense. Revisar todos los cambios realizados por '{user}' en las últimas 24 horas.",
            "data_exfiltration":        f"Bloquear el tráfico saliente hacia {ip}. Identificar qué datos fueron transferidos. Notificar al equipo de respuesta a incidentes.",
            "c2_beacon":                f"Bloquear {ip} en el firewall perimetral. Analizar el proceso que genera el tráfico. Escanear el endpoint en busca de malware.",
            "privilege_escalation_night": f"Verificar si '{user}' tenía autorización para operar a esa hora. Revisar todos los comandos ejecutados. Considerar restablecer credenciales.",
            "multi_vector_attack":      f"Activar el protocolo de respuesta a incidentes. Aislar los sistemas afectados. Bloquear {ip} en todos los controles de red.",
        }

        return {
            "explanation":        expl,
            "severity":           anomaly.get("anomaly_severity", "alta"),
            "likely_attack":      attack,
            "recommended_action": actions.get(attack, f"Investigar el evento con mayor detalle. Revisar logs adicionales relacionados con {ip}."),
        }

    def save_explanation(self, anomaly_id: int, explanation: dict):
        """Actualiza la anomalía en la BD con la explicación de Claude."""
        with self._connect() as conn:
            conn.execute("""
                UPDATE anomalies SET
                    explanation        = ?,
                    severity           = ?,
                    likely_attack      = ?,
                    recommended_action = ?
                WHERE id = ?
            """, (
                explanation.get("explanation"),
                explanation.get("severity"),
                explanation.get("likely_attack"),
                explanation.get("recommended_action"),
                anomaly_id,
            ))
            conn.commit()

    def explain_batch(self, limit: int = 10, delay: float = 0.5):
        """
        Explica las próximas `limit` anomalías sin explicación.

        delay: segundos entre llamadas (evita rate limiting de la API)
        """
        anomalies = self.load_unexplained_anomalies(limit=limit)

        if not anomalies:
            print("✓ Todas las anomalías ya tienen explicación.")
            return 0

        print(f"\n  Explicando {len(anomalies)} anomalías con Claude API...")
        print(f"  (modo: {'API real' if self.client else 'simulado — sin API key'})\n")

        explained = 0
        for i, row in enumerate(anomalies, 1):
            anomaly_id = row["anomaly_id"]
            print(f"  [{i}/{len(anomalies)}] Evento #{row['event_id']} "
                  f"— {row['event_type']} "
                  f"— {row.get('src_ip', 'sin IP')}")

            result = self.explain_anomaly(event=row, anomaly=row)

            if result:
                self.save_explanation(anomaly_id, result)
                print(f"         ✓ {result['severity'].upper()}: "
                      f"{result['likely_attack']}")
                print(f"           {result['explanation'][:80]}...")
                explained += 1
            else:
                print(f"         ✗ No se pudo explicar")

            # Pausa entre llamadas para no saturar la API
            if self.client and i < len(anomalies):
                time.sleep(delay)

        print(f"\n  ✓ {explained}/{len(anomalies)} anomalías explicadas")
        return explained

    def get_explained_anomalies(self, limit: int = 50) -> pd.DataFrame:
        """Retorna anomalías con explicación para el dashboard."""
        with self._connect() as conn:
            return pd.read_sql_query("""
                SELECT
                    a.id, a.method, a.score, a.rule_name,
                    a.explanation, a.severity as anomaly_severity,
                    a.likely_attack, a.recommended_action,
                    a.detected_at,
                    e.timestamp, e.source, e.event_type,
                    e.src_ip, e.dst_ip, e.user,
                    e.hour_of_day, e.is_night, e.severity,
                    e.bytes_total, e.extra
                FROM anomalies a
                JOIN events e ON e.id = a.event_id
                WHERE a.explanation IS NOT NULL
                ORDER BY e.severity DESC, a.score ASC
                LIMIT ?
            """, conn, params=(limit,))

    def summary(self) -> dict:
        """Resumen del estado de las explicaciones."""
        with self._connect() as conn:
            total       = conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
            explained   = conn.execute(
                "SELECT COUNT(*) FROM anomalies WHERE explanation IS NOT NULL"
            ).fetchone()[0]
            by_severity = dict(conn.execute("""
                SELECT severity, COUNT(*) FROM anomalies
                WHERE explanation IS NOT NULL
                GROUP BY severity
            """).fetchall())
            by_attack   = dict(conn.execute("""
                SELECT likely_attack, COUNT(*) FROM anomalies
                WHERE likely_attack IS NOT NULL
                GROUP BY likely_attack
                ORDER BY COUNT(*) DESC
            """).fetchall())

        return {
            "total_anomalies":   total,
            "explained":         explained,
            "pending":           total - explained,
            "by_severity":       by_severity,
            "by_attack_type":    by_attack,
        }


# ---------------------------------------------------------------------------
# FUNCIÓN PÚBLICA PARA IMPORTAR DESDE DETECTOR
# ---------------------------------------------------------------------------

def explain_anomalies_batch(db_path: str, limit: int = 10):
    client = ClaudeSecurityClient(db_path=db_path)
    return client.explain_batch(limit=limit)


# ---------------------------------------------------------------------------
# EJECUCIÓN DIRECTA
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Claude API client — explica anomalías de seguridad"
    )
    ap.add_argument("--db",       default="data/log_analyzer.db")
    ap.add_argument("--limit",    type=int, default=10,
                    help="Número de anomalías a explicar (default: 10)")
    ap.add_argument("--event-id", type=int, default=None,
                    help="Explicar un evento específico por su ID")
    ap.add_argument("--summary",  action="store_true",
                    help="Solo mostrar resumen sin llamar a la API")
    ap.add_argument("--delay",    type=float, default=0.5,
                    help="Segundos entre llamadas a la API (default: 0.5)")
    args = ap.parse_args()

    db_path = ROOT / args.db
    if not db_path.exists():
        print(f"ERROR: {db_path} no existe.")
        print("Ejecuta primero: python run_etl.py && python core/detector.py")
        sys.exit(1)

    print(f"\n{'='*55}")
    print("  Log Analyzer — Claude API Client")
    print(f"{'='*55}")

    client = ClaudeSecurityClient(db_path=str(db_path))

    if args.summary:
        s = client.summary()
        print(f"\n  Estado de explicaciones:")
        print(f"    Total anomalías : {s['total_anomalies']:,}")
        print(f"    Explicadas      : {s['explained']:,}")
        print(f"    Pendientes      : {s['pending']:,}")
        if s["by_severity"]:
            print(f"\n  Por severidad:")
            for sev, n in s["by_severity"].items():
                print(f"    {sev:<12} {n:>5}")
        if s["by_attack_type"]:
            print(f"\n  Por tipo de ataque:")
            for attack, n in list(s["by_attack_type"].items())[:8]:
                print(f"    {attack:<30} {n:>5}")
        return

    # Explicar anomalías
    n = client.explain_batch(limit=args.limit, delay=args.delay)

    # Mostrar resumen final
    print(f"\n{'='*55}")
    s = client.summary()
    print(f"  Resumen final:")
    print(f"    Anomalías explicadas : {s['explained']:,} / {s['total_anomalies']:,}")
    print(f"    Pendientes           : {s['pending']:,}")

    if s["by_attack_type"]:
        print(f"\n  Tipos de ataque detectados:")
        for attack, count in list(s["by_attack_type"].items())[:6]:
            print(f"    {attack:<30} {count:>5}")

    print(f"\n  Siguiente paso:")
    print(f"    python app.py  → Dashboard Streamlit")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    main()
