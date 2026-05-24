"""
parser.py — Log Analyzer: Auth.log Parser
==========================================
Parsea archivos /var/log/auth.log de Linux extrayendo eventos
estructurados con campos normalizados listos para análisis con Pandas.

Eventos soportados:
  - SSH: failed password, accepted password, publickey, disconnected
  - SSH: invalid user, connection closed, max auth exceeded
  - sudo: comandos ejecutados, sesiones, fallos de autenticación
  - PAM: session open/close, authentication failure
  - su: cambios de usuario
  - CRON: sesiones de tareas programadas
  - useradd / userdel / usermod: gestión de cuentas
  - systemd-logind: login de sesiones de escritorio / consola

Uso:
    from parser import parse_file, parse_line

    df = parse_file("data/sample_auth.log")
    print(df.head())
    print(df["event_type"].value_counts())
"""

import re
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# 1. PATRÓN BASE
#    Captura el encabezado común a TODAS las líneas de auth.log:
#    MONTH DAY HH:MM:SS HOST PROCESS[PID]: MESSAGE
# ---------------------------------------------------------------------------
BASE_PATTERN = re.compile(
    r'^(?P<month>[A-Za-z]+)\s+'          # Mes abreviado: Jan, Feb … Dec
    r'(?P<day>\s?\d{1,2})\s+'           # Día (con posible espacio si < 10)
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+'  # HH:MM:SS
    r'(?P<host>\S+)\s+'                  # Hostname
    r'(?P<process>[\w\-\.@]+)'           # Proceso: sshd, sudo, CRON, PAM…
    r'(?:\[(?P<pid>\d+)\])?'            # PID opcional entre corchetes
    r':\s+'                              # Dos puntos + espacio
    r'(?P<message>.+)$'                  # Resto del mensaje
)

# ---------------------------------------------------------------------------
# 2. PATRONES SSH — proceso "sshd"
# ---------------------------------------------------------------------------

# Fallo de contraseña (usuario válido o inválido)
# "Failed password for root from 1.2.3.4 port 54231 ssh2"
# "Failed password for invalid user admin from 1.2.3.4 port 54231 ssh2"
SSH_FAILED_PASSWORD = re.compile(
    r'Failed password for (?:invalid user )?'
    r'(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)'
    r'\s+port\s+(?P<port>\d+)'
)

# Autenticación aceptada (password o publickey)
# "Accepted password for deploy from 10.0.0.2 port 22 ssh2"
# "Accepted publickey for ubuntu from 10.0.0.5 port 49812 ssh2"
SSH_ACCEPTED = re.compile(
    r'Accepted\s+(?P<method>password|publickey|keyboard-interactive|gssapi\S*)'
    r'\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)'
    r'\s+port\s+(?P<port>\d+)'
)

# Usuario inválido (sin credenciales todavía)
# "Invalid user webmaster from 203.0.113.42 port 61234"
SSH_INVALID_USER = re.compile(
    r'Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)'
    r'(?:\s+port\s+(?P<port>\d+))?'
)

# Conexión cerrada (normal o con preauth)
# "Connection closed by 192.168.1.1 port 22 [preauth]"
# "Disconnected from 192.168.1.1 port 22"
# "Disconnected from invalid user hacker 203.0.113.1 port 44210 [preauth]"
SSH_DISCONNECTED = re.compile(
    r'(?:Disconnected from|Connection closed by)'
    r'(?:\s+invalid user\s+(?P<user>\S+))?'
    r'\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)'
    r'(?:\s+\[(?P<reason>[^\]]+)\])?'
)

# Demasiados intentos de autenticación
# "error: maximum authentication attempts exceeded for root from 1.2.3.4 port 22"
SSH_MAX_ATTEMPTS = re.compile(
    r'maximum authentication attempts exceeded'
    r'(?:\s+for\s+(?:invalid user\s+)?(?P<user>\S+))?'
    r'\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)'
)

# Conexión rechazada / no permitida
# "User root from 1.2.3.4 not allowed because not listed in AllowUsers"
SSH_NOT_ALLOWED = re.compile(
    r'User\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)\s+not allowed'
    r'(?:\s+because\s+(?P<reason>.+))?'
)

# Recepción de clave pública (intento, antes de aceptar)
# "Received disconnect from 1.2.3.4 port 22: 11: ..."
SSH_RECEIVED_DISCONNECT = re.compile(
    r'Received disconnect from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)'
    r'(?::\s*(?P<code>\d+):\s*(?P<reason>.+))?'
)

# Apertura/cierre de sesión SSH autenticada
# "pam_unix(sshd:session): session opened for user ubuntu by (uid=0)"
SSH_SESSION = re.compile(
    r'pam_unix\(sshd:session\):\s+session\s+(?P<action>opened|closed)'
    r'\s+for\s+user\s+(?P<user>\S+)'
)

# ---------------------------------------------------------------------------
# 3. PATRONES SUDO — proceso "sudo"
# ---------------------------------------------------------------------------

# Comando ejecutado con éxito
# "deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"
SUDO_COMMAND = re.compile(
    r'(?P<user>\S+)\s*:'
    r'(?:.*?TTY=(?P<tty>\S+))?'
    r'(?:.*?PWD=(?P<pwd>\S+))?'
    r'(?:.*?USER=(?P<target_user>\S+))?'
    r'(?:.*?COMMAND=(?P<command>.+))?$'
)

# Fallo de autenticación en sudo
# "sudo: pam_unix(sudo:auth): authentication failure; logname=deploy uid=1000 ..."
SUDO_AUTH_FAILURE = re.compile(
    r'pam_unix\(sudo:auth\):\s+authentication failure'
    r'(?:.*?user=(?P<user>\S+))?'
    r'(?:.*?ruser=(?P<ruser>\S+))?'
)

# Sesión sudo abierta/cerrada
# "pam_unix(sudo:session): session opened for user root by deploy(uid=1001)"
SUDO_SESSION = re.compile(
    r'pam_unix\(sudo:session\):\s+session\s+(?P<action>opened|closed)'
    r'\s+for\s+user\s+(?P<target_user>\S+)'
    r'(?:\s+by\s+(?P<user>\S+))?'
)

# ---------------------------------------------------------------------------
# 4. PATRONES SU — proceso "su" o "su-l"
# ---------------------------------------------------------------------------

# "Successful su for root by ubuntu"
SU_SUCCESS = re.compile(
    r'Successful su for\s+(?P<target_user>\S+)\s+by\s+(?P<user>\S+)'
)

# "FAILED su for root by www-data"
SU_FAILED = re.compile(
    r'FAILED su for\s+(?P<target_user>\S+)\s+by\s+(?P<user>\S+)'
)

# ---------------------------------------------------------------------------
# 5. PATRONES PAM — proceso con "pam_unix" en el mensaje
# ---------------------------------------------------------------------------

# "pam_unix(login:auth): authentication failure; logname= uid=0 ruser= user=root"
PAM_AUTH_FAILURE = re.compile(
    r'pam_unix\((?P<service>[^:]+):auth\):\s+authentication failure'
    r'(?:.*?user=(?P<user>\S+))?'
    r'(?:.*?rhost=(?P<ip>[\d.]+))?'
)

# "pam_unix(sshd:auth): check pass; user unknown"
PAM_UNKNOWN_USER = re.compile(
    r'pam_unix\((?P<service>[^:]+):auth\):\s+check pass;\s+user unknown'
)

# "pam_tally2: user root (uid=0) tally 5, deny 3"
PAM_TALLY = re.compile(
    r'pam_tally2?(?:2)?:\s+user\s+(?P<user>\S+)'
    r'(?:\s+\(uid=(?P<uid>\d+)\))?'
    r'\s+tally\s+(?P<tally>\d+)'
)

# ---------------------------------------------------------------------------
# 6. PATRONES CRON — proceso "CRON"
# ---------------------------------------------------------------------------

# "pam_unix(cron:session): session opened for user root by (uid=0)"
CRON_SESSION = re.compile(
    r'pam_unix\(cron:session\):\s+session\s+(?P<action>opened|closed)'
    r'\s+for\s+user\s+(?P<user>\S+)'
)

# ---------------------------------------------------------------------------
# 7. PATRONES GESTIÓN DE USUARIOS
# ---------------------------------------------------------------------------

# "new user: name=hacker, UID=1002, GID=1002, ..."
USERADD = re.compile(
    r'new user:\s+name=(?P<user>\S+?),\s+'
    r'UID=(?P<uid>\d+),\s+GID=(?P<gid>\d+)'
)

# "delete user 'hacker'"
USERDEL = re.compile(
    r"(?:delete|remove) user '?(?P<user>\S+?)'?"
)

# "change user 'ubuntu' password"
USERMOD = re.compile(
    r"(?:change|changed) user '?(?P<user>\S+?)'?"
)

# ---------------------------------------------------------------------------
# 8. PATRONES SYSTEMD-LOGIND — sesiones de escritorio / consola
# ---------------------------------------------------------------------------

# "New session 5 of user ubuntu."
LOGIND_NEW_SESSION = re.compile(
    r'New session\s+(?P<session_id>\S+)\s+of user\s+(?P<user>\S+)'
)

# "Removed session 5."
LOGIND_REMOVED_SESSION = re.compile(
    r'Removed session\s+(?P<session_id>\S+)'
)

# ---------------------------------------------------------------------------
# 9. MAPA DE EVENTOS
#    Lista ordenada: (nombre_evento, patrón, proceso_filtro)
#    proceso_filtro=None significa "aplica a cualquier proceso"
# ---------------------------------------------------------------------------
EVENT_MAP = [
    # SSH
    ("ssh_accepted",           SSH_ACCEPTED,            "sshd"),
    ("ssh_failed_password",    SSH_FAILED_PASSWORD,     "sshd"),
    ("ssh_invalid_user",       SSH_INVALID_USER,        "sshd"),
    ("ssh_max_attempts",       SSH_MAX_ATTEMPTS,        "sshd"),
    ("ssh_not_allowed",        SSH_NOT_ALLOWED,         "sshd"),
    ("ssh_disconnected",       SSH_DISCONNECTED,        "sshd"),
    ("ssh_recv_disconnect",    SSH_RECEIVED_DISCONNECT, "sshd"),
    ("ssh_session",            SSH_SESSION,             "sshd"),
    # sudo
    ("sudo_command",           SUDO_COMMAND,            "sudo"),
    ("sudo_auth_failure",      SUDO_AUTH_FAILURE,       "sudo"),
    ("sudo_session",           SUDO_SESSION,            "sudo"),
    # su
    ("su_success",             SU_SUCCESS,              None),
    ("su_failed",              SU_FAILED,               None),
    # PAM
    ("pam_auth_failure",       PAM_AUTH_FAILURE,        None),
    ("pam_unknown_user",       PAM_UNKNOWN_USER,        None),
    ("pam_tally",              PAM_TALLY,               None),
    # CRON
    ("cron_session",           CRON_SESSION,            "CRON"),
    # Gestión de usuarios
    ("useradd",                USERADD,                 None),
    ("userdel",                USERDEL,                 None),
    ("usermod",                USERMOD,                 None),
    # systemd-logind
    ("logind_new_session",     LOGIND_NEW_SESSION,      None),
    ("logind_removed_session", LOGIND_REMOVED_SESSION,  None),
]

# Grupos que cada patrón puede devolver → columnas del DataFrame
EXTRACTABLE_FIELDS = [
    "user", "target_user", "ip", "port", "method",
    "command", "tty", "pwd", "action", "reason",
    "service", "uid", "gid", "tally", "ruser",
    "session_id", "code",
]

# ---------------------------------------------------------------------------
# 10. FUNCIONES PRINCIPALES
# ---------------------------------------------------------------------------

def parse_line(line: str, year: Optional[int] = None) -> Optional[dict]:
    """
    Parsea una sola línea de auth.log.

    Parámetros
    ----------
    line : str
        Línea cruda del archivo.
    year : int, opcional
        Año a usar en el timestamp (auth.log no lo incluye).
        Por defecto usa el año actual.

    Retorna
    -------
    dict con los campos extraídos, o None si la línea no hace match.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    base_match = BASE_PATTERN.match(line)
    if not base_match:
        return None

    base = base_match.groupdict()
    year = year or datetime.now().year

    # Construir timestamp — auth.log omite el año
    try:
        ts_str = f"{base['month'].strip()} {base['day'].strip()} {base['time']} {year}"
        timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")
    except ValueError:
        return None

    record: dict = {
        "timestamp":    timestamp,
        "host":         base["host"],
        "process":      base["process"],
        "pid":          int(base["pid"]) if base["pid"] else None,
        "message":      base["message"],
        "event_type":   "unknown",
        "raw_line":     line,
    }
    # Inicializar todos los campos extraíbles en None
    for field in EXTRACTABLE_FIELDS:
        record[field] = None

    msg     = base["message"]
    process = base["process"].lower()

    for event_type, pattern, proc_filter in EVENT_MAP:
        # Si el patrón tiene filtro de proceso, verificar coincidencia
        if proc_filter and proc_filter.lower() not in process:
            continue

        m = pattern.search(msg)
        if not m:
            continue

        record["event_type"] = event_type
        for field in EXTRACTABLE_FIELDS:
            try:
                value = m.group(field)
                if value is not None:
                    record[field] = value.strip()
            except IndexError:
                pass  # El patrón no tiene ese grupo — es normal

        # Conversiones de tipo
        if record["port"] is not None:
            try:
                record["port"] = int(record["port"])
            except (ValueError, TypeError):
                record["port"] = None

        if record["uid"] is not None:
            try:
                record["uid"] = int(record["uid"])
            except (ValueError, TypeError):
                record["uid"] = None

        break  # Primer match gana

    return record


def parse_file(
    path: str | Path,
    year: Optional[int] = None,
    add_features: bool = True,
) -> pd.DataFrame:
    """
    Lee un archivo auth.log completo y retorna un DataFrame normalizado.

    Parámetros
    ----------
    path : str | Path
        Ruta al archivo de log.
    year : int, opcional
        Año para los timestamps (por defecto: año actual).
    add_features : bool
        Si True, agrega columnas derivadas útiles para detección
        de anomalías (hour_of_day, is_night, failed_last_5min, etc.)

    Retorna
    -------
    pd.DataFrame con todos los eventos parseados.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"No se encontró el archivo: {path}")

    records   = []
    skipped   = 0
    total     = 0

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            total += 1
            result = parse_line(line, year)
            if result:
                records.append(result)
            else:
                skipped += 1

    print(f"✓ Total líneas leídas : {total}")
    print(f"✓ Eventos parseados   : {len(records)}")
    print(f"  Líneas omitidas     : {skipped}  "
          f"({100 * skipped / max(total, 1):.1f}%)")

    if not records:
        return pd.DataFrame()

    df = pd.DataFrame(records)

    # Tipos de dato
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=False)
    df["port"]      = pd.to_numeric(df["port"],  errors="coerce").astype("Int64")
    df["pid"]       = pd.to_numeric(df["pid"],   errors="coerce").astype("Int64")
    df["uid"]       = pd.to_numeric(df["uid"],   errors="coerce").astype("Int64")
    df["tally"]     = pd.to_numeric(df["tally"], errors="coerce").astype("Int64")

    df["event_type"] = df["event_type"].astype("category")
    df["process"]    = df["process"].astype("category")

    df = df.sort_values("timestamp").reset_index(drop=True)

    if add_features:
        df = _add_features(df)

    return df


def _add_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Agrega columnas derivadas para detección de anomalías:
      - hour_of_day      : hora del evento (0-23)
      - is_night         : True si ocurre entre 22:00 y 05:59
      - is_weekend       : True si es sábado o domingo
      - is_failure       : True para cualquier evento de fallo
      - is_privilege_op  : True para sudo/su
      - failed_last_5min : cuántos fallos SSH llegaron de la misma IP
                           en los últimos 5 minutos (ventana rodante)
      - brute_force_flag : True si failed_last_5min >= 5
      - success_after_fail: True si el evento es ssh_accepted Y la misma
                            IP tuvo >= 3 fallos en la última hora
    """
    df["hour_of_day"] = df["timestamp"].dt.hour
    df["is_night"]    = (
        df["hour_of_day"].between(22, 23) |
        df["hour_of_day"].between(0, 5)
    )
    df["is_weekend"] = df["timestamp"].dt.dayofweek >= 5

    FAILURE_EVENTS    = {"ssh_failed_password", "ssh_invalid_user",
                         "ssh_max_attempts",    "pam_auth_failure",
                         "sudo_auth_failure",   "su_failed"}
    PRIVILEGE_EVENTS  = {"sudo_command", "sudo_session",
                         "su_success",   "su_failed"}

    df["is_failure"]      = df["event_type"].isin(FAILURE_EVENTS)
    df["is_privilege_op"] = df["event_type"].isin(PRIVILEGE_EVENTS)

    # --- Ventana rodante de fallos SSH por IP (5 minutos) ---
    df["failed_last_5min"] = 0

    ssh_fails = df[df["is_failure"] & df["ip"].notna()].copy()

    if not ssh_fails.empty:
        ssh_fails = ssh_fails.set_index("timestamp")

        def rolling_count(grp: pd.Series) -> pd.Series:
            return grp.rolling("5min").sum()

        rolling = (
            ssh_fails.assign(one=1)
            .groupby("ip")["one"]
            .transform(rolling_count)
        )
        rolling.index = ssh_fails.index
        ssh_fails["rolling_fails"] = rolling

        df = df.merge(
            ssh_fails[["rolling_fails"]],
            left_index=True,
            right_index=True,
            how="left",
        )
        df["failed_last_5min"] = (
            df.pop("rolling_fails").fillna(0).astype(int)
        )

    df["brute_force_flag"] = df["failed_last_5min"] >= 5

    # --- Login exitoso tras fallos previos (posible credential stuffing) ---
    accepted = df[df["event_type"] == "ssh_accepted"].copy()
    if not accepted.empty and not ssh_fails.empty:
        # Para cada login exitoso, verificar si la IP tuvo >= 3 fallos
        # en la hora anterior
        fail_counts = (
            ssh_fails.reset_index()
            .groupby("ip")
            .size()
            .rename("total_fails")
        )
        accepted["success_after_fail"] = accepted["ip"].map(
            lambda ip: fail_counts.get(ip, 0) >= 3
        )
        df = df.merge(
            accepted[["success_after_fail"]],
            left_index=True, right_index=True, how="left",
        )
        df["success_after_fail"] = df["success_after_fail"].fillna(False)
    else:
        df["success_after_fail"] = False

    return df


# ---------------------------------------------------------------------------
# 11. UTILIDADES DE ANÁLISIS
# ---------------------------------------------------------------------------

def top_offending_ips(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Retorna las N IPs con más eventos de fallo."""
    fails = df[df["is_failure"] & df["ip"].notna()]
    return (
        fails.groupby("ip")["is_failure"]
        .count()
        .sort_values(ascending=False)
        .head(n)
        .rename("failed_attempts")
        .reset_index()
    )


def brute_force_candidates(df: pd.DataFrame) -> pd.DataFrame:
    """IPs que superaron el umbral de brute force (5+ fallos en 5 min)."""
    return (
        df[df["brute_force_flag"]]
        [["timestamp", "ip", "user", "failed_last_5min", "event_type"]]
        .drop_duplicates(subset=["ip"])
        .sort_values("failed_last_5min", ascending=False)
    )


def privilege_escalations(df: pd.DataFrame) -> pd.DataFrame:
    """Eventos de escalada de privilegios, especialmente nocturnos."""
    return (
        df[df["is_privilege_op"]]
        [["timestamp", "host", "process", "user",
          "target_user", "command", "is_night"]]
        .sort_values("timestamp")
    )


def summary(df: pd.DataFrame) -> dict:
    """Resumen estadístico rápido del DataFrame parseado."""
    return {
        "total_events":        len(df),
        "unique_ips":          df["ip"].nunique(),
        "unique_users":        df["user"].nunique(),
        "event_type_counts":   df["event_type"].value_counts().to_dict(),
        "brute_force_ips":     len(brute_force_candidates(df)),
        "night_privilege_ops": int(
            df[df["is_privilege_op"] & df["is_night"]].shape[0]
        ),
        "success_after_fail":  int(df["success_after_fail"].sum()),
        "time_range":          {
            "start": str(df["timestamp"].min()),
            "end":   str(df["timestamp"].max()),
        },
    }


# ---------------------------------------------------------------------------
# 12. EJECUCIÓN DIRECTA (modo CLI básico)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    import json

    log_path = sys.argv[1] if len(sys.argv) > 1 else "data/sample_auth.log"

    print(f"\n{'='*55}")
    print(f"  Log Analyzer — parser.py")
    print(f"  Archivo: {log_path}")
    print(f"{'='*55}\n")

    df = parse_file(log_path)

    if df.empty:
        print("No se encontraron eventos. Verifica el archivo.")
        sys.exit(1)

    print("\n--- Resumen general ---")
    print(json.dumps(summary(df), indent=2, default=str))

    print("\n--- Top 10 IPs ofensivas ---")
    print(top_offending_ips(df).to_string(index=False))

    print("\n--- Candidatos a brute force ---")
    bf = brute_force_candidates(df)
    if bf.empty:
        print("  Ninguno detectado.")
    else:
        print(bf.to_string(index=False))

    print("\n--- Escaladas de privilegio nocturnas ---")
    pe = privilege_escalations(df)
    pe_night = pe[pe["is_night"]]
    if pe_night.empty:
        print("  Ninguna detectada.")
    else:
        print(pe_night.to_string(index=False))
