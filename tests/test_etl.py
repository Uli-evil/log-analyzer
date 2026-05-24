"""
test_etl.py — Tests del Pipeline ETL
=====================================
Verifica que los tres módulos del ETL funcionen correctamente
y que la conexión entre Ingesta → ETL sea válida.

Uso:
    python tests/test_etl.py

No requiere pytest — corre con Python stdlib directamente.
"""

import sys
import os
import json
import traceback
import pandas as pd
from pathlib import Path

# Agregar el directorio raíz al path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


def test(name: str):
    """Decorador simple para reportar resultados."""
    def decorator(fn):
        def wrapper():
            try:
                fn()
                print(f"  ✓ {name}")
                return True
            except AssertionError as e:
                print(f"  ✗ {name}")
                print(f"    Error: {e}")
                return False
            except Exception as e:
                print(f"  ✗ {name}")
                print(f"    Exception: {type(e).__name__}: {e}")
                traceback.print_exc()
                return False
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# TESTS DE EXTRACCIÓN (parser.py)
# ---------------------------------------------------------------------------

@test("parser.py — lee sample_auth.log")
def test_parser_lee_archivo():
    from core.parser import parse_file
    auth_path = ROOT / "data" / "raw" / "sample_auth.log"
    assert auth_path.exists(), f"No existe {auth_path} — ejecuta: python scripts/ingestor.py"
    df = parse_file(str(auth_path))
    assert not df.empty, "El DataFrame está vacío"
    assert len(df) > 100, f"Muy pocos eventos: {len(df)}"


@test("parser.py — columnas requeridas presentes")
def test_parser_columnas():
    from core.parser import parse_file
    df = parse_file(str(ROOT / "data" / "raw" / "sample_auth.log"))
    required = ["timestamp", "event_type", "ip", "user", "process"]
    for col in required:
        assert col in df.columns, f"Columna faltante: {col}"


@test("parser.py — detecta eventos de tipo ssh_failed_password")
def test_parser_detecta_fallos():
    from core.parser import parse_file
    df = parse_file(str(ROOT / "data" / "raw" / "sample_auth.log"))
    fallos = df[df["event_type"] == "ssh_failed_password"]
    assert len(fallos) > 0, "No se detectaron fallos SSH — verifica el log generado"


@test("parser.py — detecta actividad nocturna")
def test_parser_noche():
    from core.parser import parse_file
    df = parse_file(str(ROOT / "data" / "raw" / "sample_auth.log"))
    assert "is_night" in df.columns, "Columna is_night faltante"
    noche = df[df["is_night"] == True]
    assert len(noche) > 0, "No hay eventos nocturnos en el log generado"


@test("parser.py — timestamps son datetime válidos")
def test_parser_timestamps():
    from core.parser import parse_file
    df = parse_file(str(ROOT / "data" / "raw" / "sample_auth.log"))
    assert pd.api.types.is_datetime64_any_dtype(df["timestamp"]), \
        "timestamp no es datetime"
    nulos = df["timestamp"].isna().sum()
    assert nulos == 0, f"{nulos} timestamps nulos"


# ---------------------------------------------------------------------------
# TESTS DE TRANSFORMACIÓN (transformer.py)
# ---------------------------------------------------------------------------

@test("transformer.py — transform_linux produce schema unificado")
def test_transformer_linux():
    from core.parser import parse_file
    from core.transformer import transform_linux, UNIFIED_SCHEMA
    df_raw = parse_file(str(ROOT / "data" / "raw" / "sample_auth.log"))
    df = transform_linux(df_raw)
    assert not df.empty
    for col in UNIFIED_SCHEMA:
        assert col in df.columns, f"Columna faltante en schema: {col}"


@test("transformer.py — transform_network procesa CSV de red")
def test_transformer_network():
    from core.transformer import transform_network
    net_path = ROOT / "data" / "raw" / "network_traffic.csv"
    assert net_path.exists(), "No existe network_traffic.csv"
    df = transform_network(pd.read_csv(str(net_path)))
    assert not df.empty
    assert "severity" in df.columns
    assert df["severity"].between(1, 5).all(), "Severidad fuera de rango 1-5"


@test("transformer.py — transform_windows procesa CSV de eventos")
def test_transformer_windows():
    from core.transformer import transform_windows
    win_path = ROOT / "data" / "raw" / "windows_events.csv"
    assert win_path.exists(), "No existe windows_events.csv"
    df = transform_windows(pd.read_csv(str(win_path)))
    assert not df.empty
    # Event ID 1102 debe tener severidad 5
    critical = df[df["raw_event_type"] == "EventID_1102"]
    if len(critical) > 0:
        assert (critical["severity"] == 5).all(), "1102 debe tener severidad 5"


@test("transformer.py — unify combina las 3 fuentes correctamente")
def test_transformer_unify():
    from core.parser import parse_file
    from core.transformer import (transform_linux, transform_network,
                                   transform_windows, unify)
    df_linux = transform_linux(parse_file(str(ROOT / "data" / "raw" / "sample_auth.log")))
    df_net   = transform_network(pd.read_csv(str(ROOT / "data" / "raw" / "network_traffic.csv")))
    df_win   = transform_windows(pd.read_csv(str(ROOT / "data" / "raw" / "windows_events.csv")))
    df_all   = unify([df_linux, df_net, df_win])

    assert len(df_all) == len(df_linux) + len(df_net) + len(df_win), \
        "El total unificado no coincide con la suma de las partes"
    assert set(df_all["source"].unique()) == {"linux", "network", "windows"}, \
        "Faltan fuentes en el DataFrame unificado"
    assert df_all["timestamp"].is_monotonic_increasing, \
        "El DataFrame unificado no está ordenado por timestamp"


@test("transformer.py — severidad entre 1 y 5 en el unificado")
def test_transformer_severidad():
    from core.parser import parse_file
    from core.transformer import (transform_linux, transform_network,
                                   transform_windows, unify)
    df_all = unify([
        transform_linux(parse_file(str(ROOT / "data" / "raw" / "sample_auth.log"))),
        transform_network(pd.read_csv(str(ROOT / "data" / "raw" / "network_traffic.csv"))),
        transform_windows(pd.read_csv(str(ROOT / "data" / "raw" / "windows_events.csv"))),
    ])
    assert df_all["severity"].between(1, 5).all(), \
        f"Severidades fuera de rango:\n{df_all['severity'].value_counts()}"


# ---------------------------------------------------------------------------
# TESTS DE CARGA (loader.py)
# ---------------------------------------------------------------------------

@test("loader.py — init_db crea las 4 tablas")
def test_loader_init():
    from core.loader import Loader
    import sqlite3
    db_path = ROOT / "data" / "test_temp.db"
    loader = Loader(str(db_path))
    loader.init_db()

    conn = sqlite3.connect(str(db_path))
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()]
    conn.close()
    db_path.unlink()  # limpiar

    for tabla in ["events", "anomalies", "detection_rules", "run_log"]:
        assert tabla in tables, f"Tabla faltante: {tabla}"


@test("loader.py — inserta eventos y los recupera")
def test_loader_insert():
    from core.parser import parse_file
    from core.transformer import transform_linux, unify
    from core.loader import Loader

    db_path = ROOT / "data" / "test_insert.db"
    loader = Loader(str(db_path))
    loader.init_db()

    df = unify([transform_linux(
        parse_file(str(ROOT / "data" / "raw" / "sample_auth.log"))
    )])
    n = loader.insert_events(df)
    assert n > 0, "No se insertó ningún evento"

    df_back = loader.query_events(severity_min=1, limit=9999)
    assert len(df_back) == n, f"Insertados: {n}, recuperados: {len(df_back)}"

    db_path.unlink()


@test("loader.py — reglas SQL detectan eventos sospechosos")
def test_loader_reglas():
    from core.loader import Loader
    # Usar la DB principal si existe
    db_path = ROOT / "data" / "log_analyzer.db"
    if not db_path.exists():
        print("    (DB principal no existe — ejecuta python run_etl.py primero)")
        return

    loader = Loader(str(db_path))
    hits = loader.run_detection_rules()
    assert len(hits) > 0, "Las reglas SQL no detectaron ningún evento"
    assert "rule_name" in hits.columns
    assert "event_id" in hits.columns


@test("loader.py — stats retorna estructura correcta")
def test_loader_stats():
    from core.loader import Loader
    db_path = ROOT / "data" / "log_analyzer.db"
    if not db_path.exists():
        return
    stats = Loader(str(db_path)).stats()
    for key in ["total_events", "by_source", "by_severity", "critical_events"]:
        assert key in stats, f"Clave faltante en stats: {key}"
    assert stats["total_events"] > 0


# ---------------------------------------------------------------------------
# TEST DE INTEGRACIÓN — pipeline completo
# ---------------------------------------------------------------------------

@test("ETL completo — pipeline de extremo a extremo")
def test_etl_completo():
    from core.parser import parse_file
    from core.transformer import (transform_linux, transform_network,
                                   transform_windows, unify)
    from core.loader import Loader

    db_path = ROOT / "data" / "test_integration.db"
    loader = Loader(str(db_path))
    loader.init_db()

    df_all = unify([
        transform_linux(parse_file(str(ROOT / "data" / "raw" / "sample_auth.log"))),
        transform_network(pd.read_csv(str(ROOT / "data" / "raw" / "network_traffic.csv"))),
        transform_windows(pd.read_csv(str(ROOT / "data" / "raw" / "windows_events.csv"))),
    ])

    n = loader.insert_events(df_all)
    assert n > 2000, f"Muy pocos eventos insertados: {n}"

    hits = loader.run_detection_rules()
    assert len(hits) > 0, "Ninguna regla SQL disparó"

    stats = loader.stats()
    assert stats["total_events"] == n

    db_path.unlink()


# ---------------------------------------------------------------------------
# RUNNER
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n" + "="*55)
    print("  Log Analyzer — Tests del Pipeline ETL")
    print("="*55)

    test_groups = [
        ("Extracción (parser.py)", [
            test_parser_lee_archivo,
            test_parser_columnas,
            test_parser_detecta_fallos,
            test_parser_noche,
            test_parser_timestamps,
        ]),
        ("Transformación (transformer.py)", [
            test_transformer_linux,
            test_transformer_network,
            test_transformer_windows,
            test_transformer_unify,
            test_transformer_severidad,
        ]),
        ("Carga (loader.py)", [
            test_loader_init,
            test_loader_insert,
            test_loader_reglas,
            test_loader_stats,
        ]),
        ("Integración completa", [
            test_etl_completo,
        ]),
    ]

    total = 0
    passed = 0

    for group_name, tests in test_groups:
        print(f"\n{group_name}:")
        for t in tests:
            total += 1
            if t():
                passed += 1

    print(f"\n{'='*55}")
    if passed == total:
        print(f"  ✓ Todos los tests pasaron ({passed}/{total})")
        print(f"  El pipeline ETL está listo para el detector.")
    else:
        print(f"  ⚠ {passed}/{total} tests pasaron")
        print(f"  Revisa los errores y ejecuta python run_etl.py primero.")
    print("="*55 + "\n")

    sys.exit(0 if passed == total else 1)
