"""
run_etl.py — Ejecuta el Pipeline ETL completo
==============================================
Orquesta los tres pasos del ETL en orden:
    1. Ingesta  — lee los archivos de data/raw/
    2. Transform — normaliza con transformer.py
    3. Load      — inserta en SQLite con loader.py

Uso:
    python run_etl.py
    python run_etl.py --db data/mi_db.db
    python run_etl.py --rules   (solo ejecuta las reglas SQL, sin re-insertar)
"""

import sys
import json
import argparse
import pandas as pd
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.parser      import parse_file
from core.transformer import (transform_linux, transform_network,
                               transform_windows, unify, summary)
from core.loader      import Loader


def main():
    ap = argparse.ArgumentParser(description="Pipeline ETL del Log Analyzer")
    ap.add_argument("--db",    default="data/log_analyzer.db",
                    help="Ruta a la base de datos SQLite")
    ap.add_argument("--rules", action="store_true",
                    help="Solo ejecutar reglas SQL (sin re-insertar eventos)")
    args = ap.parse_args()

    loader = Loader(args.db)

    if args.rules:
        print("\n[RULES] Ejecutando reglas de detección SQL...")
        hits = loader.run_detection_rules()
        print(f"  Eventos afectados: {len(hits)}")
        print(hits["rule_name"].value_counts().to_string())
        return

    print("\n" + "="*55)
    print("  Log Analyzer — Pipeline ETL completo")
    print("="*55)

    # ── Paso 1: Inicializar DB ──────────────────────────────
    print("\n[1/4] Inicializando base de datos...")
    loader.init_db()

    # ── Paso 2: Leer y transformar fuentes ─────────────────
    print("\n[2/4] Transformando fuentes de logs...")
    dfs = []

    auth_path = Path("data/raw/sample_auth.log")
    if auth_path.exists():
        df_raw = parse_file(str(auth_path))
        dfs.append(transform_linux(df_raw))
        print(f"  ✓ Linux  : {len(dfs[-1])} eventos")
    else:
        print(f"  ⚠ No encontrado: {auth_path}")

    net_path = Path("data/raw/network_traffic.csv")
    if net_path.exists():
        dfs.append(transform_network(pd.read_csv(str(net_path))))
        print(f"  ✓ Red    : {len(dfs[-1])} flujos")
    else:
        print(f"  ⚠ No encontrado: {net_path}")

    win_path = Path("data/raw/windows_events.csv")
    if win_path.exists():
        dfs.append(transform_windows(pd.read_csv(str(win_path))))
        print(f"  ✓ Windows: {len(dfs[-1])} eventos")
    else:
        print(f"  ⚠ No encontrado: {win_path}")

    if not dfs:
        print("\n  ERROR: No se encontraron archivos en data/raw/")
        print("  Ejecuta primero: python scripts/ingestor.py")
        sys.exit(1)

    # ── Paso 3: Unificar ───────────────────────────────────
    print("\n[3/4] Unificando fuentes...")
    df_all = unify(dfs)
    print(f"  ✓ Total: {len(df_all)} eventos unificados")
    print(f"\n  Resumen:")
    s = summary(df_all)
    print(f"    Fuentes      : {s['sources']}")
    print(f"    Críticos     : {s['critical_events']}")
    print(f"    Hints anomalía: {s['anomaly_hints']}")
    print(f"    IPs únicas   : {s['unique_src_ips']}")

    # Guardar CSV intermedio
    Path("data/processed").mkdir(exist_ok=True)
    df_all.to_csv("data/processed/unified_events.csv", index=False)
    print(f"\n  CSV guardado: data/processed/unified_events.csv")

    # ── Paso 4: Cargar a SQLite ────────────────────────────
    print("\n[4/4] Cargando a SQLite...")
    n = loader.insert_events(df_all)

    # Reglas SQL
    print("\n  Ejecutando reglas de detección...")
    hits = loader.run_detection_rules()
    print(f"  Eventos que disparan reglas: {len(hits)}")
    if not hits.empty:
        print("  " + hits["rule_name"].value_counts().to_string().replace("\n", "\n  "))

    # Registrar ejecución
    loader.log_run(
        source="linux+network+windows",
        events_total=n,
        anomalies_found=len(hits),
        status="success",
    )

    # ── Resumen final ──────────────────────────────────────
    print("\n" + "="*55)
    print("  ✓ ETL completado")
    print(f"  DB: {args.db}")
    print(json.dumps(loader.stats(), indent=4))
    print("\n  Siguiente paso:")
    print("    python core/detector.py   → Isolation Forest")
    print("="*55 + "\n")


if __name__ == "__main__":
    main()
