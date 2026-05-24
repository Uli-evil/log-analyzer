"""
transformer.py — Pipeline ETL: Transformación y Feature Engineering
====================================================================
Toma los DataFrames crudos de los tres parsers y produce DataFrames
normalizados con un schema unificado listo para el detector de anomalías.

Funciones principales:
    transform_linux(df)   — normaliza logs de auth.log
    transform_network(df) — normaliza CSV de tráfico de red
    transform_windows(df) — normaliza eventos Windows
    unify(dfs)            — combina las tres fuentes en un schema común

Uso:
    from core.transformer import transform_linux, transform_network, transform_windows, unify

    df_linux = transform_linux(parse_file("data/raw/sample_auth.log"))
    df_net   = transform_network(pd.read_csv("data/raw/network_traffic.csv"))
    df_win   = transform_windows(pd.read_csv("data/raw/windows_events.csv"))
    df_all   = unify([df_linux, df_net, df_win])
"""

import re
import numpy as np
import pandas as pd
from typing import Optional

# ---------------------------------------------------------------------------
# SCHEMA UNIFICADO
# Columnas que tendrá el DataFrame final sin importar la fuente
# ---------------------------------------------------------------------------
UNIFIED_SCHEMA = [
    "timestamp",        # datetime UTC
    "source",           # 'linux' | 'network' | 'windows'
    "event_type",       # tipo de evento normalizado
    "src_ip",           # IP de origen
    "dst_ip",           # IP de destino (cuando aplica)
    "src_port",         # puerto de origen
    "dst_port",         # puerto de destino
    "user",             # usuario involucrado
    "severity",         # 1=info, 2=low, 3=medium, 4=high, 5=critical
    "is_anomaly_hint",  # True si hay señales obvias de anomalía
    # Features numéricos para Isolation Forest
    "hour_of_day",
    "is_night",         # bool → int (0/1)
    "is_weekend",       # bool → int (0/1)
    "failed_last_5min", # conteo de fallos recientes por IP
    "bytes_total",      # bytes transferidos (red) o 0
    "duration_sec",     # duración del flujo en segundos o 0
    # Metadatos
    "raw_event_type",   # event_type original antes de normalizar
    "extra",            # campo libre para info adicional
]

# Mapa de event_type específico → categoría normalizada + severidad
LINUX_SEVERITY_MAP = {
    "ssh_accepted":            ("auth_success",    1),
    "ssh_failed_password":     ("auth_failure",    3),
    "ssh_invalid_user":        ("auth_failure",    3),
    "ssh_max_attempts":        ("brute_force",     4),
    "ssh_not_allowed":         ("policy_violation",3),
    "ssh_disconnected":        ("connection",      1),
    "ssh_recv_disconnect":     ("connection",      1),
    "ssh_session":             ("session",         1),
    "sudo_command":            ("privilege_op",    2),
    "sudo_auth_failure":       ("auth_failure",    4),
    "sudo_session":            ("session",         1),
    "su_success":              ("privilege_op",    3),
    "su_failed":               ("auth_failure",    3),
    "pam_auth_failure":        ("auth_failure",    3),
    "pam_unknown_user":        ("auth_failure",    2),
    "pam_tally":               ("brute_force",     4),
    "cron_session":            ("scheduled_task",  1),
    "useradd":                 ("account_change",  4),
    "userdel":                 ("account_change",  4),
    "usermod":                 ("account_change",  3),
    "logind_new_session":      ("session",         1),
    "logind_removed_session":  ("session",         1),
    "unknown":                 ("unknown",         1),
}

WINDOWS_SEVERITY_MAP = {
    4624: ("auth_success",    1),
    4625: ("auth_failure",    3),
    4648: ("privilege_op",    4),
    4672: ("privilege_op",    4),
    4688: ("process_created", 2),
    4698: ("scheduled_task",  3),
    4720: ("account_change",  5),
    4726: ("account_change",  5),
    4740: ("brute_force",     4),
    4756: ("account_change",  3),
    4776: ("auth_failure",    3),
    4778: ("session",         1),
    4779: ("session",         1),
    7045: ("service_install", 5),
    1102: ("log_cleared",     5),   # CRÍTICO
}

NETWORK_SEVERITY_MAP = {
    "BENIGN":        ("net_normal",    1),
    "DoS":           ("dos_attack",    4),
    "PortScan":      ("recon",         3),
    "BruteForce-SSH":("brute_force",   4),
    "Botnet":        ("c2_beacon",     5),
    "Infiltration":  ("exfiltration",  5),
}


# ---------------------------------------------------------------------------
# 1. TRANSFORMADOR LINUX
# ---------------------------------------------------------------------------

def transform_linux(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normaliza el DataFrame producido por core/parser.py.
    Agrega severidad, schema unificado y features adicionales.
    """
    if df.empty:
        return pd.DataFrame(columns=UNIFIED_SCHEMA)

    out = pd.DataFrame()

    # Timestamp — asegurar UTC
    out["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    out["source"]    = "linux"

    # Event type normalizado + severidad
    def map_event(et):
        cat, sev = LINUX_SEVERITY_MAP.get(str(et), ("unknown", 1))
        return cat, sev

    mapped                = df["event_type"].astype(str).apply(map_event)
    out["event_type"]     = [x[0] for x in mapped]
    out["severity"]       = [x[1] for x in mapped]
    out["raw_event_type"] = df["event_type"].astype(str)

    # IPs y puertos
    out["src_ip"]   = df.get("source_ip", pd.Series(dtype=str))
    out["dst_ip"]   = None
    out["src_port"] = pd.to_numeric(df.get("port"), errors="coerce").astype("Int64")
    out["dst_port"] = None

    # Usuario
    out["user"] = df.get("user", pd.Series(dtype=str))

    # Elevación nocturna de severidad — sudo/su de madrugada es más sospechoso
    night_priv = df.get("is_night", False) & df["event_type"].isin(
        ["sudo_command", "su_success", "ssh_accepted"]
    )
    out.loc[night_priv, "severity"] = out.loc[night_priv, "severity"].clip(upper=5) + 1

    # Hints de anomalía
    out["is_anomaly_hint"] = (
        df.get("brute_force_flag", False) |
        df.get("success_after_fail", False) |
        (df["event_type"].isin(["useradd", "userdel", "sudo_auth_failure"]))
    ).astype(bool)

    # Features temporales
    out["hour_of_day"]    = out["timestamp"].dt.hour
    out["is_night"]       = (
        out["hour_of_day"].between(22, 23) | out["hour_of_day"].between(0, 5)
    ).astype(int)
    out["is_weekend"]     = (out["timestamp"].dt.dayofweek >= 5).astype(int)

    # Features de volumen (no aplican para logs de auth)
    out["failed_last_5min"] = df.get("failed_last_5min", 0).fillna(0).astype(int)
    out["bytes_total"]      = 0
    out["duration_sec"]     = 0

    # Extra: comando sudo si existe
    out["extra"] = df.get("command", pd.Series(dtype=str))

    return out[UNIFIED_SCHEMA].reset_index(drop=True)


# ---------------------------------------------------------------------------
# 2. TRANSFORMADOR DE RED
# ---------------------------------------------------------------------------

def transform_network(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normaliza el DataFrame de tráfico de red (formato CICIDS o generado).
    """
    if df.empty:
        return pd.DataFrame(columns=UNIFIED_SCHEMA)

    out = pd.DataFrame()

    # Timestamp
    if "timestamp" in df.columns:
        out["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    else:
        out["timestamp"] = pd.NaT

    out["source"] = "network"

    # Label → event_type normalizado + severidad
    label_col = "label" if "label" in df.columns else None

    def map_label(label):
        return NETWORK_SEVERITY_MAP.get(str(label), ("net_unknown", 2))

    if label_col:
        mapped                = df[label_col].apply(map_label)
        out["event_type"]     = [x[0] for x in mapped]
        out["severity"]       = [x[1] for x in mapped]
        out["raw_event_type"] = df[label_col].astype(str)
    else:
        out["event_type"]     = "net_unknown"
        out["severity"]       = 2
        out["raw_event_type"] = "unknown"

    # IPs y puertos — manejar nombres de columna alternativos
    src_ip_col  = next((c for c in ["src_ip", " Source IP", "Source IP"]   if c in df.columns), None)
    dst_ip_col  = next((c for c in ["dst_ip", " Destination IP", "Destination IP"] if c in df.columns), None)
    src_prt_col = next((c for c in ["src_port", " Source Port", "Source Port"]      if c in df.columns), None)
    dst_prt_col = next((c for c in ["dst_port", " Destination Port", "Destination Port"] if c in df.columns), None)

    out["src_ip"]   = df[src_ip_col].astype(str)  if src_ip_col  else None
    out["dst_ip"]   = df[dst_ip_col].astype(str)  if dst_ip_col  else None
    out["src_port"] = pd.to_numeric(df[src_prt_col], errors="coerce").astype("Int64") if src_prt_col else pd.NA
    out["dst_port"] = pd.to_numeric(df[dst_prt_col], errors="coerce").astype("Int64") if dst_prt_col else pd.NA

    out["user"] = None

    # Hints de anomalía
    anomaly_labels = {"DoS", "PortScan", "BruteForce-SSH", "Botnet", "Infiltration"}
    out["is_anomaly_hint"] = df.get("label", pd.Series(dtype=str)).isin(anomaly_labels)

    # Features temporales
    out["hour_of_day"] = out["timestamp"].dt.hour.fillna(12).astype(int)
    out["is_night"]    = (
        out["hour_of_day"].between(22, 23) | out["hour_of_day"].between(0, 5)
    ).astype(int)
    out["is_weekend"]  = (out["timestamp"].dt.dayofweek >= 5).astype(int)

    # Features de volumen
    fwd = pd.to_numeric(df.get("fwd_bytes", 0), errors="coerce").fillna(0)
    bwd = pd.to_numeric(df.get("bwd_bytes", 0), errors="coerce").fillna(0)
    out["bytes_total"] = (fwd + bwd).astype(int)

    dur_us = pd.to_numeric(df.get("flow_duration_us", 0), errors="coerce").fillna(0)
    out["duration_sec"] = (dur_us / 1_000_000).round(2)

    # failed_last_5min: conteo de flujos de brute force recientes por IP
    out["failed_last_5min"] = 0
    if label_col and src_ip_col:
        fail_mask = df[label_col].isin({"BruteForce-SSH", "DoS"})
        if fail_mask.any() and out["timestamp"].notna().any():
            tmp = out[fail_mask].copy()
            tmp = tmp.sort_values("timestamp").set_index("timestamp")
            rolling = (
                tmp.assign(one=1)
                .groupby("src_ip")["one"]
                .transform(lambda x: x.rolling("5min").sum())
            )
            rolling.index = tmp.index
            tmp["rolling"] = rolling
            out = out.merge(tmp[["rolling"]], left_index=True,
                            right_index=True, how="left")
            out["failed_last_5min"] = out.pop("rolling").fillna(0).astype(int)
    # Extra: protocolo y servicio destino
    proto   = df.get("protocol_name", df.get("protocol", "")).astype(str)
    service = df.get("dst_service", pd.Series(dtype=str)).fillna("")
    out["extra"] = proto + " → " + service

    return out[UNIFIED_SCHEMA].reset_index(drop=True)


# ---------------------------------------------------------------------------
# 3. TRANSFORMADOR WINDOWS
# ---------------------------------------------------------------------------

def transform_windows(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normaliza el DataFrame de eventos Windows (CSV generado o exportado de EVTX).
    """
    if df.empty:
        return pd.DataFrame(columns=UNIFIED_SCHEMA)

    out = pd.DataFrame()

    # Timestamp
    out["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    out["source"]    = "windows"

    # Event ID → event_type normalizado + severidad
    event_id = pd.to_numeric(df.get("event_id", 0), errors="coerce").fillna(0).astype(int)

    def map_eid(eid):
        return WINDOWS_SEVERITY_MAP.get(int(eid), ("win_other", 1))

    mapped                = event_id.apply(map_eid)
    out["event_type"]     = [x[0] for x in mapped]
    out["severity"]       = [x[1] for x in mapped]
    out["raw_event_type"] = "EventID_" + event_id.astype(str)

    # IPs y puertos
    out["src_ip"]   = df.get("source_ip", pd.Series(dtype=str))
    out["dst_ip"]   = None
    out["src_port"] = pd.to_numeric(df.get("port"), errors="coerce").astype("Int64")
    out["dst_port"] = None

    # Usuario
    out["user"] = df.get("user", pd.Series(dtype=str))

    # Hints de anomalía — event IDs críticos
    critical_ids = {1102, 4720, 4726, 4698, 7045, 4740, 4648, 4672}
    out["is_anomaly_hint"] = event_id.isin(critical_ids)

    # Severidad extra para log borrado (1102) — siempre crítico
    out.loc[event_id == 1102, "severity"] = 5

    # Features temporales
    out["hour_of_day"] = out["timestamp"].dt.hour.fillna(12).astype(int)
    out["is_night"]    = (
        out["hour_of_day"].between(22, 23) | out["hour_of_day"].between(0, 5)
    ).astype(int)
    out["is_weekend"]  = (out["timestamp"].dt.dayofweek >= 5).astype(int)

    # Fallos recientes por IP (ventana 5 min)
    out["failed_last_5min"] = 0
    fail_mask = event_id.isin({4625, 4740})
    if fail_mask.any() and out["timestamp"].notna().any() and out["src_ip"].notna().any():
        tmp = out[fail_mask & out["src_ip"].notna()].copy()
        tmp = tmp.set_index("timestamp")
        rolling = (
            tmp.assign(one=1)
            .groupby("src_ip")["one"]
            .transform(lambda x: x.rolling("5min").sum())
        )
        rolling.index = tmp.index
        tmp["rolling"] = rolling
        out = out.merge(tmp[["rolling"]], left_index=True,
                        right_index=True, how="left")
        out["failed_last_5min"] = out.pop("rolling").fillna(0).astype(int)

    out["bytes_total"]  = 0
    out["duration_sec"] = 0

    # Extra: proceso + logon_type
    proc    = df.get("process_name", pd.Series(dtype=str)).fillna("")
    logtype = df.get("logon_type_name", pd.Series(dtype=str)).fillna("")
    out["extra"] = proc.where(proc != "", logtype)

    return out[UNIFIED_SCHEMA].reset_index(drop=True)


# ---------------------------------------------------------------------------
# 4. UNIFICADOR — combina las tres fuentes
# ---------------------------------------------------------------------------

def unify(dfs: list) -> pd.DataFrame:
    """
    Combina una lista de DataFrames transformados en un único DataFrame
    con el schema unificado, ordenado por timestamp.

    Parámetros
    ----------
    dfs : list de DataFrames (resultado de transform_linux/network/windows)

    Retorna
    -------
    pd.DataFrame unificado, listo para el detector de anomalías.
    """
    valid = [df for df in dfs if not df.empty]
    if not valid:
        return pd.DataFrame(columns=UNIFIED_SCHEMA)

    combined = pd.concat(valid, ignore_index=True)
    combined = combined.sort_values("timestamp").reset_index(drop=True)

    # Severidad: clip entre 1 y 5
    combined["severity"] = combined["severity"].clip(1, 5).astype(int)

    # Asegurar tipos correctos
    combined["is_night"]       = combined["is_night"].fillna(0).astype(int)
    combined["is_weekend"]     = combined["is_weekend"].fillna(0).astype(int)
    combined["failed_last_5min"] = combined["failed_last_5min"].fillna(0).astype(int)
    combined["bytes_total"]    = combined["bytes_total"].fillna(0).astype(int)
    combined["duration_sec"]   = combined["duration_sec"].fillna(0).astype(float)
    combined["is_anomaly_hint"] = combined["is_anomaly_hint"].fillna(False).astype(bool)

    return combined


# ---------------------------------------------------------------------------
# 5. UTILIDADES
# ---------------------------------------------------------------------------

def summary(df: pd.DataFrame) -> dict:
    """Resumen estadístico del DataFrame transformado."""
    if df.empty:
        return {"error": "DataFrame vacío"}

    return {
        "total_events":    len(df),
        "sources":         df["source"].value_counts().to_dict(),
        "event_types":     df["event_type"].value_counts().head(10).to_dict(),
        "severity_dist":   df["severity"].value_counts().sort_index().to_dict(),
        "anomaly_hints":   int(df["is_anomaly_hint"].sum()),
        "unique_src_ips":  df["src_ip"].nunique(),
        "critical_events": int((df["severity"] == 5).sum()),
        "night_events":    int(df["is_night"].sum()),
        "time_range": {
            "start": str(df["timestamp"].min()),
            "end":   str(df["timestamp"].max()),
        },
    }


def get_suspicious_ips(df: pd.DataFrame, min_severity: int = 3) -> pd.DataFrame:
    """
    IPs que aparecen en eventos de severidad >= min_severity.
    Útil para correlación cruzada entre fuentes.
    """
    return (
        df[df["severity"] >= min_severity & df["src_ip"].notna()]
        .groupby("src_ip")
        .agg(
            total_events   = ("event_type", "count"),
            max_severity   = ("severity",   "max"),
            sources        = ("source",     lambda x: list(x.unique())),
            event_types    = ("event_type", lambda x: list(x.unique())),
            anomaly_hints  = ("is_anomaly_hint", "sum"),
        )
        .sort_values("max_severity", ascending=False)
        .reset_index()
    )


def cross_source_ips(df: pd.DataFrame) -> pd.DataFrame:
    """
    IPs que aparecen en MÁS DE UNA fuente simultáneamente.
    Esta es la correlación más valiosa del Log Analyzer:
    una IP en Linux + Windows + Red al mismo tiempo es señal fuerte de ataque.
    """
    ip_sources = (
        df[df["src_ip"].notna()]
        .groupby("src_ip")["source"]
        .apply(lambda x: set(x))
        .reset_index()
    )
    ip_sources.columns = ["src_ip", "sources"]
    ip_sources["n_sources"] = ip_sources["sources"].apply(len)
    ip_sources["sources"]   = ip_sources["sources"].apply(lambda s: ", ".join(sorted(s)))

    multi = ip_sources[ip_sources["n_sources"] > 1].sort_values(
        "n_sources", ascending=False
    )
    return multi


# ---------------------------------------------------------------------------
# EJECUCIÓN DIRECTA
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    import json
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

    from core.parser import parse_file

    print("\n" + "="*55)
    print("  transformer.py — Pipeline ETL")
    print("="*55)

    # Linux
    print("\n[1/3] Transformando Linux auth.log...")
    df_raw   = parse_file("data/raw/sample_auth.log")
    df_linux = transform_linux(df_raw)
    print(f"  ✓ {len(df_linux)} eventos transformados")

    # Red
    print("\n[2/3] Transformando tráfico de red...")
    df_net_raw = pd.read_csv("data/raw/network_traffic.csv")
    df_net     = transform_network(df_net_raw)
    print(f"  ✓ {len(df_net)} flujos transformados")

    # Windows
    print("\n[3/3] Transformando eventos Windows...")
    df_win_raw = pd.read_csv("data/raw/windows_events.csv")
    df_win     = transform_windows(df_win_raw)
    print(f"  ✓ {len(df_win)} eventos transformados")

    # Unificar
    print("\n[4/4] Unificando las tres fuentes...")
    df_all = unify([df_linux, df_net, df_win])
    print(f"  ✓ {len(df_all)} eventos totales")

    # Resumen
    print("\n--- Resumen unificado ---")
    print(json.dumps(summary(df_all), indent=2, default=str))

    # IPs en múltiples fuentes
    print("\n--- IPs en más de una fuente (correlación cruzada) ---")
    cross = cross_source_ips(df_all)
    if cross.empty:
        print("  Ninguna IP aparece en múltiples fuentes.")
    else:
        print(cross.to_string(index=False))

    # Guardar CSV procesado
    out_path = "data/processed/unified_events.csv"
    __import__("pathlib").Path("data/processed").mkdir(exist_ok=True)
    df_all.to_csv(out_path, index=False)
    print(f"\n✓ DataFrame unificado guardado en: {out_path}")
    print("\nSiguiente paso: core/loader.py → insertar en SQLite")
