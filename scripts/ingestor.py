"""
ingestor.py
===========
Punto de entrada unificado para la capa de ingesta del Log Analyzer.

Orquesta los tres generadores de datos y valida que los archivos
producidos sean parseables por los parsers correspondientes.

Uso:
    python scripts/ingestor.py                  # genera todo con defaults
    python scripts/ingestor.py --lines 2000     # más volumen
    python scripts/ingestor.py --validate       # genera + valida parsers
    python scripts/ingestor.py --summary        # muestra resumen de archivos
"""

import sys
import argparse
import subprocess
from pathlib import Path

BASE_DIR   = Path(__file__).parent.parent
DATA_RAW   = BASE_DIR / "data" / "raw"
SCRIPTS    = BASE_DIR / "scripts"


def run_generator(script: str, extra_args: list = None):
    cmd = [sys.executable, str(SCRIPTS / script)] + (extra_args or [])
    print(f"\n{'─'*50}")
    print(f"  Ejecutando: {script}")
    print(f"{'─'*50}")
    result = subprocess.run(cmd, capture_output=False, text=True)
    if result.returncode != 0:
        print(f"  ERROR en {script}")
    return result.returncode == 0


def validate_parsers():
    """Intenta parsear cada archivo generado para confirmar que funcionan."""
    print(f"\n{'='*50}")
    print("  Validando parsers")
    print(f"{'='*50}")

    sys.path.insert(0, str(BASE_DIR))

    # Validar auth.log
    auth_file = DATA_RAW / "sample_auth.log"
    if auth_file.exists():
        try:
            from core.parser import parse_file
            df = parse_file(str(auth_file))
            print(f"\n✓ parser.py  — {len(df)} eventos parseados de {auth_file.name}")
            print(f"  Event types: {df['event_type'].value_counts().to_dict()}")
        except Exception as e:
            print(f"\n✗ parser.py  — ERROR: {e}")
    else:
        print(f"\n⚠ {auth_file} no existe — ejecuta el generador primero")

    # Validar network CSV
    net_file = DATA_RAW / "network_traffic.csv"
    if net_file.exists():
        try:
            import pandas as pd
            df = pd.read_csv(str(net_file))
            print(f"\n✓ network CSV — {len(df)} filas cargadas de {net_file.name}")
            print(f"  Labels: {df['label'].value_counts().to_dict()}")
        except Exception as e:
            print(f"\n✗ network CSV — ERROR: {e}")
    else:
        print(f"\n⚠ {net_file} no existe — ejecuta el generador primero")

    # Validar windows events CSV
    win_file = DATA_RAW / "windows_events.csv"
    if win_file.exists():
        try:
            import pandas as pd
            df = pd.read_csv(str(win_file))
            print(f"\n✓ windows CSV — {len(df)} eventos cargados de {win_file.name}")
            print(f"  Event IDs: {df['event_id'].value_counts().to_dict()}")
        except Exception as e:
            print(f"\n✗ windows CSV — ERROR: {e}")
    else:
        print(f"\n⚠ {win_file} no existe — ejecuta el generador primero")


def summary():
    """Muestra tamaño y estadísticas de los archivos existentes."""
    print(f"\n{'='*50}")
    print("  Archivos en data/raw/")
    print(f"{'='*50}")
    files = list(DATA_RAW.glob("*")) if DATA_RAW.exists() else []
    if not files:
        print("  (vacío — ejecuta ingestor.py primero)")
        return
    for f in sorted(files):
        size_kb = f.stat().st_size / 1024
        print(f"  {f.name:<35} {size_kb:>8.1f} KB")


def main():
    ap = argparse.ArgumentParser(
        description="Ingestor maestro del Log Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python scripts/ingestor.py                   # genera todo
  python scripts/ingestor.py --lines 2000      # más volumen
  python scripts/ingestor.py --validate        # genera + valida
  python scripts/ingestor.py --summary         # solo muestra archivos
        """
    )
    ap.add_argument("--lines",    type=int,  default=500,
                    help="Líneas de auth.log a generar (default: 500)")
    ap.add_argument("--rows",     type=int,  default=1000,
                    help="Filas de CSV de red y Windows a generar (default: 1000)")
    ap.add_argument("--validate", action="store_true",
                    help="Valida los parsers después de generar")
    ap.add_argument("--summary",  action="store_true",
                    help="Muestra resumen de archivos existentes y sale")
    args = ap.parse_args()

    if args.summary:
        summary()
        return

    print(f"\n{'='*50}")
    print("  Log Analyzer — Capa de Ingesta")
    print(f"{'='*50}")
    print(f"  Destino: {DATA_RAW}")

    DATA_RAW.mkdir(parents=True, exist_ok=True)

    ok1 = run_generator("generate_auth_log.py", [
        "--lines",  str(args.lines),
        "--output", str(DATA_RAW / "sample_auth.log"),
    ])

    ok2 = run_generator("generate_network_csv.py", [
        "--rows",   str(args.rows),
        "--output", str(DATA_RAW / "network_traffic.csv"),
    ])

    ok3 = run_generator("generate_windows_events.py", [
        "--rows",   str(args.rows),
        "--output", str(DATA_RAW / "windows_events.csv"),
    ])

    summary()

    if args.validate:
        validate_parsers()

    print(f"\n{'='*50}")
    if ok1 and ok2 and ok3:
        print("  ✓ Ingesta completa. Siguiente paso:")
        print("    python scripts/ingestor.py --validate")
        print("    → luego ejecuta core/parser.py sobre los datos")
    else:
        print("  ⚠ Algunos generadores fallaron. Revisa los errores.")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    main()
