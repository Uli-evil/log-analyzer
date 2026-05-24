"""
migrate_db.py — Migra la base de datos a la nueva nomenclatura
==============================================================
Agrega las columnas nuevas y migra los datos existentes.

Uso:
    python migrate_db.py
"""

import sqlite3
import sys
from pathlib import Path

DB_PATH = Path("data/log_analyzer.db")

if not DB_PATH.exists():
    print(f"  data/log_analyzer.db no existe — se creara al correr run_etl.py")
    sys.exit(0)

print(f"  Migrando: {DB_PATH}")

conn   = sqlite3.connect(str(DB_PATH))
cursor = conn.cursor()

# Columnas nuevas a agregar
new_cols = [
    ("summary",         "TEXT"),
    ("risk_level",      "TEXT"),
    ("attack_pattern",  "TEXT"),
    ("response_action", "TEXT"),
]

# Columnas existentes
existing = [row[1] for row in cursor.execute("PRAGMA table_info(anomalies)").fetchall()]

for col, dtype in new_cols:
    if col not in existing:
        cursor.execute(f"ALTER TABLE anomalies ADD COLUMN {col} {dtype}")
        print(f"  + columna '{col}' agregada")
    else:
        print(f"  columna '{col}' ya existe")

# Migrar datos de columnas antiguas
if "explanation" in existing:
    cursor.execute("UPDATE anomalies SET summary = explanation WHERE summary IS NULL AND explanation IS NOT NULL")
    print("  datos migrados: explanation -> summary")

if "likely_attack" in existing:
    cursor.execute("UPDATE anomalies SET attack_pattern = likely_attack WHERE attack_pattern IS NULL AND likely_attack IS NOT NULL")
    print("  datos migrados: likely_attack -> attack_pattern")

if "recommended_action" in existing:
    cursor.execute("UPDATE anomalies SET response_action = recommended_action WHERE response_action IS NULL AND recommended_action IS NOT NULL")
    print("  datos migrados: recommended_action -> response_action")

conn.commit()
conn.close()
print("  base de datos actualizada correctamente")
