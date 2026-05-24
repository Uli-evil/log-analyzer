# Guía completa — Pipeline ETL del Log Analyzer
## Extracción, Transformación y Carga

---

## Software necesario — qué descargar y de qué versión

### 1. Python 3.11 (requerido)
- **Versión exacta**: Python 3.11.x (no uses 3.12+ todavía — algunas librerías tienen conflictos)
- **Descarga**: https://www.python.org/downloads/release/python-3119/
- **Archivo para Windows**: `python-3.11.9-amd64.exe`
- **Instalación**:
  1. Ejecuta el instalador
  2. IMPORTANTE: marca la casilla **"Add Python to PATH"** antes de continuar
  3. Elige "Customize installation"
  4. Cambia la ruta de instalación a `C:\Python311\` (evita rutas con espacios)
  5. Clic en Install
- **Verificar instalación**:
  ```powershell
  python --version
  # Debe mostrar: Python 3.11.x
  ```

### 2. Visual Studio Code (editor recomendado)
- **Descarga**: https://code.visualstudio.com/
- **Extensiones a instalar** (abre VS Code → Ctrl+Shift+X):
  - `Python` (Microsoft) — soporte completo de Python
  - `Pylance` — autocompletado inteligente
  - `SQLite Viewer` — ver la base de datos sin salir de VS Code
  - `Rainbow CSV` — ver los CSV con columnas coloreadas

### 3. DB Browser for SQLite (para inspeccionar la base de datos)
- **Descarga**: https://sqlitebrowser.org/dl/
- **Versión**: DB Browser for SQLite 3.12.2 (Windows installer)
- **Para qué sirve**: ver las tablas, ejecutar queries SQL manualmente,
  verificar que los datos se insertaron correctamente
- **No requiere instalación de servidor** — SQLite es un archivo local

### 4. Git (para control de versiones)
- **Descarga**: https://git-scm.com/download/win
- **Instalación**: siguiente, siguiente, siguiente (opciones por defecto están bien)
- **Verificar**:
  ```powershell
  git --version
  # Debe mostrar: git version 2.x.x
  ```

---

## Estructura del proyecto después del ETL

```
log-analyzer/
│
├── core/                          ← MÓDULOS DEL ETL
│   ├── parser.py                  ← EXTRACCIÓN: lee logs crudos con Regex
│   ├── transformer.py             ← TRANSFORMACIÓN: normaliza con Pandas
│   └── loader.py                  ← CARGA: inserta en SQLite
│
├── data/
│   ├── raw/                       ← Datos de entrada (logs crudos)
│   │   ├── sample_auth.log        ← Logs Linux (generado)
│   │   ├── network_traffic.csv    ← Tráfico de red (generado)
│   │   └── windows_events.csv     ← Eventos Windows (generado)
│   │
│   └── processed/                 ← Datos de salida (ya procesados)
│       ├── unified_events.csv     ← DataFrame unificado (output del ETL)
│       └── log_analyzer.db        ← Base de datos SQLite
│
├── scripts/                       ← Generadores de datos de prueba
│   ├── ingestor.py
│   ├── generate_auth_log.py
│   ├── generate_network_csv.py
│   └── generate_windows_events.py
│
├── tests/                         ← Tests del ETL
│   └── test_etl.py
│
├── docs/                          ← Esta guía y documentación
│   ├── GUIA_ETL_PASO_A_PASO.md   ← Este archivo
│   └── SCHEMA_SQL.md              ← Documentación del schema de BD
│
├── run_etl.py                     ← Punto de entrada — corre todo el ETL
├── requirements.txt               ← Dependencias Python
├── .env.example                   ← Plantilla de variables de entorno
└── README.md
```

---

## Paso 1 — Configurar el entorno

### 1.1 Abrir PowerShell en la carpeta del proyecto

```powershell
# Opción A: desde el Explorador de Windows
# Clic derecho en la carpeta log-analyzer → "Abrir en Terminal"

# Opción B: desde PowerShell
cd "C:\Proyectos\Log Analyzer\log-analyzer"
```

### 1.2 Verificar que estás en la carpeta correcta

```powershell
pwd
# Debe mostrar: C:\Proyectos\Log Analyzer\log-analyzer

ls
# Debe mostrar: core  data  docs  scripts  requirements.txt  run_etl.py  ...
```

### 1.3 Crear y activar el entorno virtual

```powershell
# Crear entorno virtual
python -m venv venv

# Activar
.\venv\Scripts\activate

# Verificar que está activado (verás (venv) al inicio)
# (venv) PS C:\Proyectos\Log Analyzer\log-analyzer>
```

### 1.4 Instalar dependencias del ETL

```powershell
pip install -r requirements.txt
```

Esto instala:
- `pandas` — manipulación de DataFrames
- `numpy` — operaciones numéricas
- `sqlalchemy` — ORM para SQLite/PostgreSQL
- `python-dotenv` — cargar variables de entorno
- `scikit-learn` — Machine Learning (para el siguiente módulo)

**Tiempo estimado**: 3-5 minutos dependiendo de tu conexión.

### 1.5 Verificar instalación

```powershell
python -c "import pandas, numpy, sqlalchemy; print('OK — dependencias del ETL instaladas')"
# Debe mostrar: OK — dependencias del ETL instaladas
```

---

## Paso 2 — Preparar las fuentes de datos (Extracción)

El módulo de Extracción es `core/parser.py`. Lee los tres archivos de `data/raw/` y produce DataFrames estructurados.

### 2.1 Generar los datos de prueba

```powershell
python scripts/ingestor.py
```

Verás:
```
Generando ~500 líneas de auth.log simulado...
✓ Archivo generado : data/raw/sample_auth.log
Generando 1000 flujos de red...
✓ CSV generado : data/raw/network_traffic.csv
Generando 800 eventos de Windows Security Log...
✓ CSV generado : data/raw/windows_events.csv
```

### 2.2 Verificar que el parser funciona

```powershell
python -c "
from core.parser import parse_file
df = parse_file('data/raw/sample_auth.log')
print('Eventos parseados:', len(df))
print(df['event_type'].value_counts().to_string())
"
```

Resultado esperado:
```
Eventos parseados: 876
event_type
ssh_session            453
ssh_accepted           227
ssh_failed_password     80
sudo_command            70
...
```

### 2.3 Qué hace parser.py exactamente

```
auth.log (texto libre)
       ↓
   BASE_PATTERN   ← extrae: timestamp, host, proceso, pid, mensaje
       ↓
   22 patrones    ← extrae: usuario, IP, puerto, tipo de evento
       ↓
   lista de dicts ← estructura limpia
       ↓
   pd.DataFrame() ← listo para transformer.py
```

---

## Paso 3 — Normalizar los datos (Transformación)

El módulo de Transformación es `core/transformer.py`. Toma los DataFrames crudos y los convierte en un schema unificado de 17 columnas.

### 3.1 Probar el transformer manualmente

```powershell
python -c "
import pandas as pd
from core.parser import parse_file
from core.transformer import transform_linux, transform_network, transform_windows, unify, summary

# Transformar cada fuente
df_linux = transform_linux(parse_file('data/raw/sample_auth.log'))
df_net   = transform_network(pd.read_csv('data/raw/network_traffic.csv'))
df_win   = transform_windows(pd.read_csv('data/raw/windows_events.csv'))

# Unificar
df_all = unify([df_linux, df_net, df_win])

# Ver resumen
import json
print(json.dumps(summary(df_all), indent=2, default=str))
"
```

### 3.2 Qué hace transformer.py exactamente

```
DataFrame Linux (event_type categórico, ip como source_ip)
DataFrame Red   (label como BENIGN/DoS/..., src_ip, dst_ip)
DataFrame Win   (event_id como 4624/4625/..., source_ip)
       ↓
   Normalización de nombres de columna
   Mapeo a severidad 1-5
   Conversión de timestamps a UTC
   Creación de features: hour_of_day, is_night, is_weekend
   Cálculo de failed_last_5min (ventana rodante 5 min)
       ↓
   Schema unificado de 17 columnas (igual para las 3 fuentes)
       ↓
   un solo DataFrame con 2,676 filas
```

### 3.3 Schema unificado — las 17 columnas

| Columna | Tipo | Descripción |
|---|---|---|
| timestamp | datetime UTC | cuándo ocurrió el evento |
| source | str | linux / network / windows |
| event_type | str | categoría normalizada del evento |
| src_ip | str | IP de origen del evento |
| dst_ip | str | IP de destino (cuando aplica) |
| src_port | Int64 | puerto de origen |
| dst_port | Int64 | puerto de destino |
| user | str | usuario involucrado |
| severity | int | 1=info, 2=low, 3=medium, 4=high, 5=critical |
| is_anomaly_hint | bool | señal obvia de anomalía |
| hour_of_day | int | hora del evento (0-23) |
| is_night | int | 1 si ocurre entre 22:00 y 06:00 |
| is_weekend | int | 1 si es sábado o domingo |
| failed_last_5min | int | fallos recientes de la misma IP |
| bytes_total | int | bytes transferidos (solo red) |
| duration_sec | float | duración del flujo en segundos |
| extra | str | info adicional (comando, protocolo, etc.) |

---

## Paso 4 — Cargar en SQLite (Carga)

El módulo de Carga es `core/loader.py`. Crea la base de datos, inserta los eventos y ejecuta las 7 reglas de detección SQL.

### 4.1 Probar el loader manualmente

```powershell
python -c "
from core.loader import Loader

loader = Loader('data/log_analyzer.db')
loader.init_db()

import json
print(json.dumps(loader.stats(), indent=2))
"
```

### 4.2 Ver la base de datos en DB Browser

1. Abre DB Browser for SQLite
2. Clic en "Abrir base de datos"
3. Navega a `C:\Proyectos\Log Analyzer\log-analyzer\data\`
4. Selecciona `log_analyzer.db`
5. Verás 4 tablas: `events`, `anomalies`, `detection_rules`, `run_log`

### 4.3 Queries SQL que puedes ejecutar en DB Browser

```sql
-- Ver los 10 eventos más críticos
SELECT timestamp, source, event_type, src_ip, user, severity
FROM events
WHERE severity = 5
ORDER BY timestamp DESC
LIMIT 10;

-- IPs con más fallos
SELECT src_ip, COUNT(*) as intentos
FROM events
WHERE event_type = 'auth_failure'
  AND src_ip IS NOT NULL
GROUP BY src_ip
ORDER BY intentos DESC;

-- Actividad nocturna sospechosa
SELECT timestamp, source, event_type, user, extra
FROM events
WHERE is_night = 1
  AND severity >= 4
ORDER BY timestamp;

-- Correlación: misma IP en múltiples fuentes
SELECT src_ip,
       COUNT(DISTINCT source) as fuentes,
       GROUP_CONCAT(DISTINCT source) as en_fuentes,
       MAX(severity) as severidad_max
FROM events
WHERE src_ip IS NOT NULL
  AND severity >= 3
GROUP BY src_ip
HAVING COUNT(DISTINCT source) > 1
ORDER BY fuentes DESC, severidad_max DESC;
```

---

## Paso 5 — Ejecutar el Pipeline ETL completo

Este es el paso más importante. Un solo comando ejecuta los 4 pasos en orden:

```powershell
python run_etl.py
```

### Output esperado

```
=======================================================
  Log Analyzer — Pipeline ETL completo
=======================================================

[1/4] Inicializando base de datos...
✓ Base de datos inicializada: data/log_analyzer.db
  Reglas cargadas: 7

[2/4] Transformando fuentes de logs...
  ✓ Linux  : 876 eventos
  ✓ Red    : 1000 flujos
  ✓ Windows: 800 eventos

[3/4] Unificando fuentes...
  ✓ Total: 2,676 eventos unificados
  Resumen:
    Fuentes       : {'network': 1000, 'linux': 876, 'windows': 800}
    Críticos      : 91
    Hints anomalía: 320
    IPs únicas    : 21

  CSV guardado: data/processed/unified_events.csv

[4/4] Cargando a SQLite...
✓ 2676 eventos insertados en log_analyzer.db

  Ejecutando reglas de detección...
  Eventos que disparan reglas: 884
  cross_source_ip     644  ← misma IP en múltiples fuentes
  c2_beacon           106  ← tráfico de botnet
  data_exfiltration    72  ← exfiltración de datos
  night_privilege_op   58  ← actividad nocturna
  audit_log_cleared     2  ← log borrado (crítico)
  new_account_created   2  ← usuario nuevo (backdoor)

=======================================================
  ✓ ETL completado
=======================================================
```

---

## Paso 6 — Cómo conecta con la etapa anterior (Ingesta)

La conexión entre Ingesta y ETL es directa — los archivos de `data/raw/` son el puente:

```
ETAPA ANTERIOR: INGESTA
scripts/ingestor.py
      ↓ produce
data/raw/sample_auth.log      ← texto libre
data/raw/network_traffic.csv  ← CSV estructurado
data/raw/windows_events.csv   ← CSV de eventos Windows

ETAPA ACTUAL: ETL
core/parser.py      ← lee data/raw/*.log
core/transformer.py ← normaliza los DataFrames
core/loader.py      ← persiste en SQLite
      ↓ produce
data/processed/unified_events.csv  ← DataFrame unificado
data/log_analyzer.db               ← base de datos SQLite

ETAPA SIGUIENTE: DETECTOR
core/detector.py    ← lee de log_analyzer.db
                    ← aplica Isolation Forest
                    ← escribe en tabla anomalies
```

### Si cambias los datos de ingesta, re-corre el ETL

```powershell
# Regenerar datos con más volumen
python scripts/ingestor.py --lines 2000 --rows 3000

# Re-ejecutar el ETL
python run_etl.py
```

---

## Paso 7 — Verificar que todo funciona con los tests

```powershell
python tests/test_etl.py
```

Resultado esperado:
```
✓ test_parser_linux     — 876 eventos, 0 errores
✓ test_transformer      — 17 columnas, tipos correctos
✓ test_loader           — DB creada, 7 reglas SQL
✓ test_etl_completo     — 2676 eventos en DB
✓ test_reglas_sql       — 884 eventos detectados
Todos los tests pasaron (5/5)
```

---

## Problemas comunes y soluciones

### Error: ModuleNotFoundError: No module named 'pandas'
```powershell
# El venv no está activado
.\venv\Scripts\activate
pip install -r requirements.txt
```

### Error: No se encontró data/raw/sample_auth.log
```powershell
# Primero genera los datos
python scripts/ingestor.py
```

### Error: database is locked
```powershell
# DB Browser tiene la DB abierta — ciérralo y vuelve a correr
python run_etl.py
```

### Warning de Pandas sobre fechas
```
UserWarning: Parsing dates in %d/%m/%Y format...
```
Este warning es inofensivo — los datos se procesan correctamente.
Para silenciarlo puedes ignorarlo o actualizar pandas: `pip install pandas --upgrade`

### El ETL tardó demasiado
Con 1000 filas debe correr en menos de 10 segundos.
Si tarda más, verifica que no hay otro proceso usando la DB.

---

## Resumen de comandos — referencia rápida

```powershell
# Activar entorno
.\venv\Scripts\activate

# Generar datos de prueba
python scripts/ingestor.py

# Ejecutar ETL completo
python run_etl.py

# Solo ejecutar reglas SQL (sin reinsertar)
python run_etl.py --rules

# Ejecutar tests
python tests/test_etl.py

# Ver stats de la DB
python -c "from core.loader import Loader; import json; print(json.dumps(Loader('data/log_analyzer.db').stats(), indent=2))"
```

---

## Siguiente etapa — Detector de anomalías

Con el ETL completo y la DB poblada, el siguiente módulo es `core/detector.py`:

```powershell
python core/detector.py
```

El detector:
1. Lee los 2,676 eventos de `log_analyzer.db`
2. Entrena un Isolation Forest con 6 features numéricos
3. Marca los eventos anómalos en la tabla `anomalies`
4. Los eventos marcados se envían a Claude API para explicación

El archivo `data/processed/unified_events.csv` ya contiene todo lo que necesita el detector.
