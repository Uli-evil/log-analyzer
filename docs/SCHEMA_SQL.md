# Schema SQL — Log Analyzer Database

## Tablas

### events — tabla principal
Almacena todos los eventos normalizados de las tres fuentes.

```sql
CREATE TABLE events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT,           -- ISO 8601 UTC
    source           TEXT,           -- 'linux' | 'network' | 'windows'
    event_type       TEXT,           -- categoría normalizada
    raw_event_type   TEXT,           -- tipo original antes de normalizar
    src_ip           TEXT,           -- IP de origen
    dst_ip           TEXT,           -- IP de destino
    src_port         INTEGER,
    dst_port         INTEGER,
    user             TEXT,
    severity         INTEGER,        -- 1=info 2=low 3=med 4=high 5=critical
    is_anomaly_hint  INTEGER,        -- 0 | 1
    hour_of_day      INTEGER,        -- 0-23
    is_night         INTEGER,        -- 1 si 22:00-06:00
    is_weekend       INTEGER,        -- 1 si sab o dom
    failed_last_5min INTEGER,        -- fallos IP últimos 5 min
    bytes_total      INTEGER,        -- bytes transferidos
    duration_sec     REAL,           -- duración flujo en segundos
    extra            TEXT,           -- cmd, protocolo, etc.
    inserted_at      TEXT            -- cuándo se insertó
);
```

### anomalies — resultados del detector
```sql
CREATE TABLE anomalies (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id           INTEGER REFERENCES events(id),
    method             TEXT,   -- 'isolation_forest' | 'sql_rule' | 'combined'
    score              REAL,   -- score ML (más negativo = más anómalo)
    rule_name          TEXT,   -- nombre de la regla SQL si aplica
    explanation        TEXT,   -- texto generado por Claude API
    severity           TEXT,   -- 'crítica' | 'alta' | 'media' | 'baja'
    likely_attack      TEXT,   -- tipo de ataque inferido
    recommended_action TEXT,
    detected_at        TEXT
);
```

### detection_rules — reglas SQL configurables
```sql
CREATE TABLE detection_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT UNIQUE,
    description TEXT,
    query       TEXT,      -- query SQL que retorna event IDs sospechosos
    severity    INTEGER,
    active      INTEGER DEFAULT 1,
    created_at  TEXT
);
```

### run_log — historial de ejecuciones
```sql
CREATE TABLE run_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT,
    finished_at     TEXT,
    source          TEXT,
    events_total    INTEGER,
    anomalies_found INTEGER,
    status          TEXT,   -- 'success' | 'error'
    message         TEXT
);
```

## Reglas SQL predefinidas

| Nombre | Descripción | Severidad |
|---|---|---|
| brute_force_ssh | IP con 5+ fallos en 5 minutos | 4 |
| night_privilege_op | sudo/su entre 22:00 y 06:00 | 4 |
| audit_log_cleared | Log de auditoría borrado (1102) | 5 |
| new_account_created | Usuario creado (useradd / 4720) | 5 |
| c2_beacon | Tráfico tipo beacon C2 | 5 |
| data_exfiltration | Ratio upload > 85% | 5 |
| cross_source_ip | IP con severidad alta en 2+ fuentes | 5 |

## Índices

```sql
CREATE INDEX idx_events_timestamp  ON events(timestamp);
CREATE INDEX idx_events_src_ip     ON events(src_ip);
CREATE INDEX idx_events_severity   ON events(severity);
CREATE INDEX idx_events_source     ON events(source);
CREATE INDEX idx_events_event_type ON events(event_type);
```

## Queries útiles de referencia

```sql
-- Distribución por fuente y severidad
SELECT source, severity, COUNT(*) as total
FROM events
GROUP BY source, severity
ORDER BY source, severity;

-- Top 10 IPs atacantes
SELECT src_ip, COUNT(*) as eventos, MAX(severity) as max_sev
FROM events
WHERE severity >= 3 AND src_ip IS NOT NULL
GROUP BY src_ip
ORDER BY max_sev DESC, eventos DESC
LIMIT 10;

-- Timeline de eventos críticos
SELECT timestamp, source, event_type, src_ip, user, extra
FROM events
WHERE severity = 5
ORDER BY timestamp;

-- Reglas que más dispararon
SELECT rule_name, COUNT(*) as hits
FROM anomalies
GROUP BY rule_name
ORDER BY hits DESC;
```
