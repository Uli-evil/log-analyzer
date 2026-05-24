"""
generate_network_csv.py
=======================
Genera un archivo CSV de tráfico de red simulado en formato
compatible con CICIDS-2017, con ataques etiquetados:

  - Tráfico BENIGN (normal)
  - DoS — flujos de alta frecuencia desde una IP
  - PortScan — muchos destinos, pocos bytes
  - BruteForce — múltiples SYN hacia puerto 22
  - Botnet — beacon C2 (flujos largos, pocos bytes)
  - Infiltration — alta ratio de upload (exfiltración)

Uso:
    python scripts/generate_network_csv.py
    python scripts/generate_network_csv.py --rows 2000 --output data/raw/network_traffic.csv
"""

import random
import argparse
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)
np.random.seed(42)

NORMAL_IPS    = [f"192.168.1.{i}" for i in range(10, 30)]
EXTERNAL_IPS  = [f"10.0.0.{i}" for i in range(1, 20)]
ATTACKER_IP   = "203.0.113.42"
VICTIM_IP     = "192.168.1.15"
C2_IP         = "198.51.100.99"

COMMON_PORTS  = [80, 443, 22, 53, 8080, 3306, 5432, 3389]
PROTOCOLS     = [6, 17, 6, 6, 6]   # TCP predomina


def rand_port(low=1024, high=65535):
    return random.randint(low, high)


def base_record(dt, src_ip, dst_ip, src_port, dst_port, proto=6) -> dict:
    return {
        "timestamp":       dt.strftime("%d/%m/%Y %H:%M:%S"),
        "src_ip":          src_ip,
        "src_port":        src_port,
        "dst_ip":          dst_ip,
        "dst_port":        dst_port,
        "protocol":        proto,
    }


def benign_record(dt) -> dict:
    src = random.choice(NORMAL_IPS)
    dst = random.choice(EXTERNAL_IPS)
    r = base_record(dt, src, dst, rand_port(), random.choice(COMMON_PORTS))
    duration = random.randint(100_000, 10_000_000)
    fwd_pkts = random.randint(5, 50)
    bwd_pkts = random.randint(3, 40)
    fwd_bytes = fwd_pkts * random.randint(200, 1500)
    bwd_bytes = bwd_pkts * random.randint(200, 1500)
    r.update({
        "flow_duration_us":   duration,
        "fwd_packets":        fwd_pkts,
        "bwd_packets":        bwd_pkts,
        "fwd_bytes":          fwd_bytes,
        "bwd_bytes":          bwd_bytes,
        "flow_bytes_per_sec": round((fwd_bytes + bwd_bytes) / (duration / 1e6), 2),
        "flow_pkts_per_sec":  round((fwd_pkts + bwd_pkts) / (duration / 1e6), 2),
        "syn_count":          1,
        "fin_count":          1,
        "rst_count":          0,
        "ack_count":          random.randint(5, 50),
        "psh_count":          random.randint(2, 10),
        "avg_pkt_size":       random.randint(200, 1200),
        "init_win_fwd":       65535,
        "init_win_bwd":       65535,
        "label":              "BENIGN",
    })
    return r


def dos_record(dt) -> dict:
    """DoS: alta frecuencia, muchos paquetes, duración corta."""
    r = base_record(dt, ATTACKER_IP, VICTIM_IP, rand_port(), 80)
    duration = random.randint(1_000, 50_000)      # muy corto
    fwd_pkts = random.randint(500, 2000)
    r.update({
        "flow_duration_us":   duration,
        "fwd_packets":        fwd_pkts,
        "bwd_packets":        random.randint(0, 5),
        "fwd_bytes":          fwd_pkts * random.randint(40, 60),
        "bwd_bytes":          random.randint(0, 500),
        "flow_bytes_per_sec": round(fwd_pkts * 50 / (duration / 1e6), 2),
        "flow_pkts_per_sec":  round(fwd_pkts / (duration / 1e6), 2),
        "syn_count":          fwd_pkts,
        "fin_count":          0,
        "rst_count":          random.randint(0, 3),
        "ack_count":          0,
        "psh_count":          0,
        "avg_pkt_size":       random.randint(40, 64),
        "init_win_fwd":       1024,
        "init_win_bwd":       0,
        "label":              "DoS",
    })
    return r


def portscan_record(dt) -> dict:
    """Port scan: muchos destinos/puertos, casi sin datos."""
    dst_ip = random.choice(NORMAL_IPS)
    dst_port = random.randint(1, 65535)
    r = base_record(dt, ATTACKER_IP, dst_ip, rand_port(), dst_port)
    duration = random.randint(100, 2_000)         # muy corto
    r.update({
        "flow_duration_us":   duration,
        "fwd_packets":        1,
        "bwd_packets":        0,
        "fwd_bytes":          random.randint(40, 80),
        "bwd_bytes":          0,
        "flow_bytes_per_sec": 0,
        "flow_pkts_per_sec":  round(1 / (duration / 1e6), 2),
        "syn_count":          1,
        "fin_count":          0,
        "rst_count":          1,
        "ack_count":          0,
        "psh_count":          0,
        "avg_pkt_size":       54,
        "init_win_fwd":       1024,
        "init_win_bwd":       0,
        "label":              "PortScan",
    })
    return r


def brute_force_record(dt) -> dict:
    """Brute force SSH: muchos SYN al puerto 22, fallos."""
    r = base_record(dt, ATTACKER_IP, VICTIM_IP, rand_port(), 22)
    duration = random.randint(500_000, 3_000_000)
    fwd_pkts = random.randint(10, 30)
    bwd_pkts = random.randint(8, 25)
    r.update({
        "flow_duration_us":   duration,
        "fwd_packets":        fwd_pkts,
        "bwd_packets":        bwd_pkts,
        "fwd_bytes":          fwd_pkts * random.randint(60, 120),
        "bwd_bytes":          bwd_pkts * random.randint(60, 120),
        "flow_bytes_per_sec": round((fwd_pkts + bwd_pkts) * 90 / (duration / 1e6), 2),
        "flow_pkts_per_sec":  round((fwd_pkts + bwd_pkts) / (duration / 1e6), 2),
        "syn_count":          fwd_pkts,
        "fin_count":          0,
        "rst_count":          bwd_pkts,
        "ack_count":          random.randint(5, 15),
        "psh_count":          0,
        "avg_pkt_size":       90,
        "init_win_fwd":       8192,
        "init_win_bwd":       8192,
        "label":              "BruteForce-SSH",
    })
    return r


def botnet_record(dt) -> dict:
    """Botnet beacon C2: flujo largo, muy pocos bytes (heartbeat)."""
    src = random.choice(NORMAL_IPS)           # víctima infectada
    r = base_record(dt, src, C2_IP, rand_port(), random.choice([443, 80, 8443]))
    duration = random.randint(60_000_000, 300_000_000)   # 1–5 minutos
    r.update({
        "flow_duration_us":   duration,
        "fwd_packets":        random.randint(2, 8),
        "bwd_packets":        random.randint(2, 6),
        "fwd_bytes":          random.randint(100, 400),
        "bwd_bytes":          random.randint(80, 300),
        "flow_bytes_per_sec": round(300 / (duration / 1e6), 4),
        "flow_pkts_per_sec":  round(6 / (duration / 1e6), 4),
        "syn_count":          1,
        "fin_count":          1,
        "rst_count":          0,
        "ack_count":          random.randint(4, 10),
        "psh_count":          random.randint(2, 6),
        "avg_pkt_size":       random.randint(60, 120),
        "init_win_fwd":       65535,
        "init_win_bwd":       65535,
        "label":              "Botnet",
    })
    return r


def infiltration_record(dt) -> dict:
    """Exfiltración: muchísimo más upload que download."""
    src = VICTIM_IP
    dst = ATTACKER_IP
    r = base_record(dt, src, dst, rand_port(), random.choice([443, 80, 53]))
    duration = random.randint(10_000_000, 60_000_000)
    fwd_bytes = random.randint(500_000, 5_000_000)   # enorme upload
    bwd_bytes = random.randint(200, 1_000)            # mínimo download
    fwd_pkts  = fwd_bytes // 1400
    bwd_pkts  = random.randint(2, 5)
    r.update({
        "flow_duration_us":   duration,
        "fwd_packets":        fwd_pkts,
        "bwd_packets":        bwd_pkts,
        "fwd_bytes":          fwd_bytes,
        "bwd_bytes":          bwd_bytes,
        "flow_bytes_per_sec": round((fwd_bytes + bwd_bytes) / (duration / 1e6), 2),
        "flow_pkts_per_sec":  round((fwd_pkts + bwd_pkts) / (duration / 1e6), 2),
        "syn_count":          1,
        "fin_count":          1,
        "rst_count":          0,
        "ack_count":          fwd_pkts,
        "psh_count":          fwd_pkts // 2,
        "avg_pkt_size":       1400,
        "init_win_fwd":       65535,
        "init_win_bwd":       65535,
        "label":              "Infiltration",
    })
    return r


ATTACK_GENERATORS = [
    (dos_record,         0.08),
    (portscan_record,    0.10),
    (brute_force_record, 0.07),
    (botnet_record,      0.05),
    (infiltration_record,0.05),
]


def generate_csv(n_rows: int = 1000) -> pd.DataFrame:
    records = []
    dt = datetime(2024, 5, 19, 8, 0, 0)

    for _ in range(n_rows):
        dt += timedelta(seconds=random.randint(1, 30))
        roll = random.random()
        cumulative = 0
        generated = False
        for gen_fn, prob in ATTACK_GENERATORS:
            cumulative += prob
            if roll < cumulative:
                records.append(gen_fn(dt))
                generated = True
                break
        if not generated:
            records.append(benign_record(dt))

    df = pd.DataFrame(records)
    # Mezclar para que los ataques no estén agrupados al final
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df


def main():
    ap = argparse.ArgumentParser(description="Generador de CSV de tráfico de red")
    ap.add_argument("--rows",   type=int, default=1000)
    ap.add_argument("--output", type=str, default="data/raw/network_traffic.csv")
    args = ap.parse_args()

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    print(f"Generando {args.rows} flujos de red...")
    df = generate_csv(args.rows)
    df.to_csv(out, index=False)

    print(f"✓ CSV generado : {out}")
    print(f"  Total filas  : {len(df)}")
    print(f"\nDistribución de etiquetas:")
    print(df["label"].value_counts().to_string())
    print(f"\nUso siguiente:")
    print(f"  from core.network_csv_parser import parse_cicids_csv")
    print(f"  df = parse_cicids_csv('{out}')")


if __name__ == "__main__":
    main()
