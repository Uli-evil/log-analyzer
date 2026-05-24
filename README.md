# Log Analyzer — Detección de Anomalías con IA

Pipeline completo de análisis de logs de seguridad con detección de anomalías usando Machine Learning y Claude API.

---

## Arquitectura

```
Fuentes de logs
    ├── Linux auth.log      → core/parser.py
    ├── Windows Event Log   → core/evtx_parser.py
    └── Tráfico de red CSV  → core/network_csv_parser.py
            ↓
      Pipeline ETL (Pandas + Regex)
            ↓
      Almacenamiento SQL (SQLite / PostgreSQL)
            ↓
      Detección de anomalías (Isolation Forest + reglas SQL)
            ↓
      Claude API (explicación de alertas)
            ↓
      Dashboard Streamlit (demo pública)
```

---

## Instalación

### Paso 1 — Clonar y crear entorno virtual

```bash
git clone https://github.com/tu-usuario/log-analyzer.git
cd log-analyzer

python -m venv venv
source venv/bin/activate        # Linux / Mac
# venv\Scripts\activate         # Windows PowerShell
```

### Paso 2 — Instalar dependencias

```bash
pip install -r requirements.txt
```

> **Nota**: `python-evtx` requiere Python 3.8+. En Windows puede requerir Visual C++ Build Tools.

### Paso 3 — Variables de entorno

```bash
cp .env.example .env
# Editar .env y agregar tu ANALYZER_API_KEY
```

---

## Uso rápido — Capa de Ingesta

### Generar todos los datos de práctica de una vez

```bash
python scripts/ingestor.py
```

Genera tres archivos en `data/raw/`:
- `sample_auth.log` — logs de autenticación Linux con anomalías
- `network_traffic.csv` — tráfico de red con ataques etiquetados
- `windows_events.csv` — eventos Windows Security Log

### Verificar que los parsers funcionan

```bash
python scripts/ingestor.py --validate
```

### Ver archivos generados

```bash
python scripts/ingestor.py --summary
```

---

## Generar datos individualmente

### Linux auth.log

```bash
# 500 líneas (default)
python scripts/generate_auth_log.py

# 2000 líneas en ruta personalizada
python scripts/generate_auth_log.py --lines 2000 --output data/raw/mi_auth.log
```

**Anomalías incluidas:**
- Brute force SSH desde `203.0.113.42` (~75 intentos)
- Login exitoso de `deploy` tras 5 fallos (credential stuffing)
- Comandos `sudo` sospechosos a las 03:17 (shell reversa, wget)
- Escaneo de usuarios desde `198.51.100.77`

### Tráfico de red CSV

```bash
python scripts/generate_network_csv.py --rows 1000
```

**Ataques etiquetados:**
- `DoS` — alta frecuencia, flujos cortos
- `PortScan` — 1 paquete por destino, sin respuesta
- `BruteForce-SSH` — muchos SYN al puerto 22
- `Botnet` — beacon C2 (flujos largos, <1 KB)
- `Infiltration` — ratio upload > 85%

### Eventos Windows

```bash
python scripts/generate_windows_events.py --rows 800
```

**Event IDs incluidos:**

| ID   | Evento                              | Por qué importa           |
|------|-------------------------------------|---------------------------|
| 4624 | Logon exitoso                       | Baseline normal           |
| 4625 | Logon fallido                       | Brute force               |
| 4648 | Logon con credenciales explícitas   | Movimiento lateral        |
| 4672 | Privilegios especiales              | Escalada de privilegios   |
| 4688 | Proceso creado                      | Ejecución de malware      |
| 4720 | Usuario creado                      | Backdoor                  |
| 4740 | Cuenta bloqueada                    | Brute force confirmado    |
| 1102 | **Log de auditoría borrado**        | **Señal crítica**         |

---

## Datos reales (opcional — para producción)

Para usar datasets públicos reales en lugar de datos simulados:

### CICIDS-2017 (tráfico de red)
1. Ir a: https://www.unb.ca/cic/datasets/ids-2017.html
2. Descargar cualquier CSV del día que quieras
3. Colocarlo en `data/raw/` con nombre `cicids_*.csv`

### LANL Auth Dataset (logs Linux reales)
1. Ir a: https://csr.lanl.gov/data/cyber1/
2. Descargar `auth.txt.gz` (logs de autenticación)
3. Descomprimir en `data/raw/lanl_auth.log`

### EVTX-ATTACK-SAMPLES (Windows reales)
1. `git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES`
2. Copiar cualquier `.evtx` a `data/raw/`
3. Usar `core/evtx_parser.py` para parsearlo

---

## Estructura del proyecto

```
log-analyzer/
├── app.py                      ← Dashboard Streamlit (demo pública)
├── requirements.txt
├── .env.example
├── README.md
│
├── core/
│   ├── parser.py               ← Parser de Linux auth.log
│   ├── evtx_parser.py          ← Parser de Windows EVTX
│   ├── network_csv_parser.py   ← Parser de CSV de red
│   ├── transformer.py          ← Normalización Pandas (próximo)
│   ├── loader.py               ← Carga a SQLite (próximo)
│   ├── detector.py             ← Isolation Forest (próximo)
│   └── claude_client.py        ← Claude API (próximo)
│
├── data/
│   ├── raw/                    ← Datos crudos (generados o descargados)
│   ├── processed/              ← DataFrames limpios (output del ETL)
│   └── samples/                ← Muestras pequeñas para demos
│
├── scripts/
│   ├── ingestor.py             ← Orquestador de ingesta
│   ├── generate_auth_log.py    ← Generador de auth.log
│   ├── generate_network_csv.py ← Generador de CSV de red
│   └── generate_windows_events.py ← Generador de eventos Windows
│
└── notebooks/
    └── 01_exploration.ipynb    ← Análisis exploratorio (próximo)
```

---

## Próximos pasos

Con la ingesta lista, el siguiente módulo es el **Pipeline ETL** (`core/transformer.py`):

```python
from core.parser import parse_file
from core.transformer import transform, add_features

# Linux
df_linux = parse_file("data/raw/sample_auth.log")
df_linux = add_features(df_linux)

# Red
import pandas as pd
df_net = pd.read_csv("data/raw/network_traffic.csv")

# Windows
df_win = pd.read_csv("data/raw/windows_events.csv")
```

---

## Tecnologías

| Capa              | Tecnología                              |
|-------------------|-----------------------------------------|
| Ingesta           | Python stdlib · Pandas · scapy          |
| ETL               | Pandas · Regex · NumPy                  |
| Almacenamiento    | SQLite / PostgreSQL · SQLAlchemy        |
| Detección ML      | scikit-learn (Isolation Forest)         |
| IA explicativa    | Claude API (Anthropic)                  |
| Dashboard         | Streamlit · Plotly                      |
| Despliegue        | Streamlit Cloud · GitHub Pages          |

---

## Autor

Proyecto de portafolio para el perfil **Data & Cyber Security Analyst**.  
Construido con asistencia de Claude (Anthropic).
