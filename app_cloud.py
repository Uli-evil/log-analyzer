"""
app_cloud.py - Log Analyzer para Streamlit Cloud
Version sin BD externa - lee CSV directamente y analiza en memoria
"""
import sys
import pandas as pd
import numpy as np
import plotly.express as px
from pathlib import Path
from datetime import datetime

import streamlit as st

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

st.set_page_config(page_title="Log Analyzer", page_icon="shield",
                   layout="wide", initial_sidebar_state="expanded")

COLORS = {"linux": "#89b4fa", "network": "#a6e3a1", "windows": "#fab387"}

ATTACK_LABELS = {
    "auth_failure":   "auth_failure",
    "brute_force":    "brute_force",
    "c2_beacon":      "c2_beacon",
    "exfiltration":   "data_exfiltration",
    "log_cleared":    "log_tampering",
    "account_change": "persistence_backdoor",
    "privilege_op":   "privilege_escalation",
    "recon":          "reconnaissance",
}


@st.cache_data(show_spinner=False)
def load_data():
    """Carga y procesa los datos desde CSV. Cachea el resultado."""
    from core.parser import parse_file
    from core.transformer import (transform_linux, transform_network,
                                  transform_windows, unify)

    auth = ROOT / "data" / "raw" / "sample_auth.log"
    net = ROOT / "data" / "raw" / "network_traffic.csv"
    win = ROOT / "data" / "raw" / "windows_events.csv"

    dfs = []
    if auth.exists():
        dfs.append(transform_linux(parse_file(str(auth))))
    if net.exists():
        dfs.append(transform_network(pd.read_csv(str(net))))
    if win.exists():
        dfs.append(transform_windows(pd.read_csv(str(win))))

    if not dfs:
        return pd.DataFrame(), pd.DataFrame()

    df = unify(dfs)
    df["timestamp"] = pd.to_datetime(
        df["timestamp"], errors="coerce", utc=True)

    # Deteccion de anomalias con Isolation Forest
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        feats = ["hour_of_day", "is_night", "is_weekend",
                 "failed_last_5min", "severity", "bytes_total"]
        avail = [c for c in feats if c in df.columns]
        X = df[avail].fillna(0).astype(float)
        sc = StandardScaler()
        Xs = sc.fit_transform(X)
        model = IsolationForest(contamination=0.05, n_estimators=100,
                                random_state=42, n_jobs=-1)
        df["if_pred"] = model.fit_predict(Xs)
        df["if_score"] = model.score_samples(Xs)
        df["is_ml_anomaly"] = df["if_pred"] == -1
    except Exception:
        df["is_ml_anomaly"] = False
        df["if_score"] = 0.0

    # Reglas de deteccion
    def is_rule_anomaly(row):
        if row.get("failed_last_5min", 0) >= 5:
            return True
        if row.get("event_type") == "c2_beacon":
            return True
        if row.get("event_type") == "exfiltration":
            return True
        if row.get("event_type") == "log_cleared":
            return True
        if row.get("event_type") == "account_change":
            return True
        if row.get("is_night") and row.get("event_type") == "privilege_op":
            return True
        return False

    df["is_rule_anomaly"] = df.apply(is_rule_anomaly, axis=1)
    df["is_anomaly"] = df["is_ml_anomaly"] | df["is_rule_anomaly"]

    def infer_attack(row):
        et = str(row.get("event_type", ""))
        fails = int(row.get("failed_last_5min", 0))
        night = int(row.get("is_night", 0))
        if fails >= 5:
            return "brute_force"
        if et == "c2_beacon":
            return "c2_beacon"
        if et == "exfiltration":
            return "data_exfiltration"
        if et == "log_cleared":
            return "log_tampering"
        if et == "account_change":
            return "persistence_backdoor"
        if et == "privilege_op" and night:
            return "privilege_escalation_night"
        return "anomalous_behavior"

    df["attack_pattern"] = df.apply(infer_attack, axis=1)

    def score_label(score):
        if score < -0.3:
            return "critico"
        if score < -0.15:
            return "alto"
        if score < -0.05:
            return "medio"
        return "bajo"

    df["risk_level"] = df["if_score"].apply(score_label)

    anom = df[df["is_anomaly"]].copy()
    return df, anom


# ====================== SIDEBAR ======================
with st.sidebar:
    st.title("Log Analyzer")
    st.caption("Security Anomaly Detection")
    st.divider()
    page = st.radio("Navegacion", [
        "Dashboard",
        "Anomalias detectadas",
        "Analisis de eventos",
        "Analizar mi log",
    ])

# ====================== CARGAR DATOS ======================
with st.spinner("Cargando datos de seguridad..."):
    try:
        df_all, df_anom = load_data()
    except Exception as e:
        st.error(f"Error cargando datos: {e}")
        st.stop()

if df_all.empty:
    st.error("No se encontraron archivos en data/raw/")
    st.stop()

with st.sidebar:
    st.divider()
    st.success(
        f"Sistema activo\n{len(df_all):,} eventos\n{len(df_anom):,} anomalias")

# ====================== PAGINA 1: DASHBOARD ======================
if page == "Dashboard":
    st.title("Security Operations Dashboard")
    st.caption(f"{datetime.now().strftime('%d/%m/%Y %H:%M')}")

    total = len(df_all)
    anomalias = len(df_anom)
    critical = int((df_all["severity"] == 5).sum())
    by_src = df_all["source"].value_counts().to_dict()
    top_atk = df_anom["attack_pattern"].value_counts().head(8).to_dict()

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total eventos",  f"{total:,}")
    c2.metric("Anomalias",      f"{anomalias:,}",
              delta=f"{100*anomalias/max(total, 1):.1f}%", delta_color="inverse")
    c3.metric("Criticos",       f"{critical:,}", delta_color="inverse")
    c4.metric("IPs unicas",     df_all["src_ip"].nunique())
    c5.metric("Tipos ataque",   len(top_atk))

    st.divider()
    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader("Eventos por fuente")
        df_s = pd.DataFrame(list(by_src.items()),
                            columns=["Fuente", "Eventos"])
        fig = px.pie(df_s, values="Eventos", names="Fuente",
                     color="Fuente", color_discrete_map=COLORS)
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#cdd6f4")
        st.plotly_chart(fig, use_container_width=True)

    with col_b:
        st.subheader("Top tipos de ataque detectados")
        if top_atk:
            df_a = pd.DataFrame(list(top_atk.items()),
                                columns=["Ataque", "Conteo"]).sort_values("Conteo")
            fig2 = px.bar(df_a, x="Conteo", y="Ataque", orientation="h",
                          color="Conteo",
                          color_continuous_scale=["#a6e3a1", "#fab387", "#f38ba8"])
            fig2.update_layout(plot_bgcolor="rgba(0,0,0,0)",
                               paper_bgcolor="rgba(0,0,0,0)",
                               font_color="#cdd6f4", showlegend=False)
            st.plotly_chart(fig2, use_container_width=True)

    if "hour_of_day" in df_all.columns:
        st.subheader("Mapa de calor — Actividad por hora y severidad")
        heat = df_all.groupby(["hour_of_day", "severity"]
                              ).size().unstack(fill_value=0)
        fig3 = px.imshow(heat.T,
                         labels=dict(x="Hora", y="Severidad", color="Eventos"),
                         color_continuous_scale=[
                             "#1e1e2e", "#f9e2af", "#f38ba8"],
                         aspect="auto")
        fig3.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#cdd6f4")
        st.plotly_chart(fig3, use_container_width=True)

    st.subheader("Eventos en el tiempo")
    df_plot = df_all.dropna(subset=["timestamp"]).sort_values("timestamp")
    fig4 = px.scatter(df_plot, x="timestamp", y="severity",
                      color="source", color_discrete_map=COLORS, opacity=0.6,
                      labels={"timestamp": "Hora", "severity": "Severidad", "source": "Fuente"})
    fig4.add_hline(y=4, line_dash="dash", line_color="#f38ba8",
                   annotation_text="Umbral alto")
    fig4.update_layout(plot_bgcolor="rgba(0,0,0,0)",
                       paper_bgcolor="rgba(0,0,0,0)", font_color="#cdd6f4")
    st.plotly_chart(fig4, use_container_width=True)


# ====================== PAGINA 2: ANOMALIAS ======================
elif page == "Anomalias detectadas":
    st.title("Anomalias Detectadas")

    if df_anom.empty:
        st.info("Sin anomalias detectadas.")
        st.stop()

    c1, c2 = st.columns(2)
    fuente = c1.selectbox("Fuente", ["Todas", "linux", "network", "windows"])
    min_sev = c2.selectbox("Severidad minima", [1, 2, 3, 4, 5], index=2)

    filtered = df_anom.copy()
    if fuente != "Todas":
        filtered = filtered[filtered["source"] == fuente]
    filtered = filtered[filtered["severity"] >= min_sev]

    st.caption(f"{len(filtered)} anomalias")

    show = [c for c in ["timestamp", "source", "event_type", "src_ip",
                        "user", "severity", "risk_level", "attack_pattern"]
            if c in filtered.columns]
    st.dataframe(filtered[show].reset_index(drop=True),
                 use_container_width=True, height=350)

    if not filtered.empty:
        st.subheader("Detalle")
        idx = st.number_input("Fila", 0, max(len(filtered)-1, 0), 0)
        row = filtered.iloc[int(idx)]
        cl, cr = st.columns(2)
        cl.markdown(f"**Fuente:** `{row.get('source', 'N/A')}`")
        cl.markdown(f"**Evento:** `{row.get('event_type', 'N/A')}`")
        cl.markdown(f"**IP:** `{row.get('src_ip', 'N/A')}`")
        cl.markdown(f"**Usuario:** `{row.get('user', 'N/A')}`")
        risk = str(row.get("risk_level", "bajo")).lower()
        color = {"critico": "#f38ba8", "alto": "#fab387",
                 "medio": "#f9e2af"}.get(risk, "#a6e3a1")
        cr.markdown(
            f"**Riesgo:** <span style='color:{color};font-weight:700'>{risk.upper()}</span>",
            unsafe_allow_html=True)
        cr.markdown(f"**Patron:** `{row.get('attack_pattern', 'N/A')}`")
        cr.markdown(f"**Severidad:** `{row.get('severity', 'N/A')}/5`")
        score = row.get("if_score", 0)
        if score:
            st.caption(
                f"Score de anomalia: {score:.3f} (mas negativo = mas anomalo)")


# ====================== PAGINA 3: ANALISIS ======================
elif page == "Analisis de eventos":
    st.title("Analisis de Eventos")

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Distribucion por fuente")
        fig = px.pie(df_all, names="source",
                     color="source", color_discrete_map=COLORS)
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#cdd6f4")
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Top tipos de evento")
        top = df_all["event_type"].value_counts().head(10).reset_index()
        top.columns = ["Tipo", "Conteo"]
        fig2 = px.bar(top.sort_values("Conteo"), x="Conteo", y="Tipo",
                      orientation="h", color="Conteo",
                      color_continuous_scale=["#89b4fa", "#f38ba8"])
        fig2.update_layout(plot_bgcolor="rgba(0,0,0,0)",
                           paper_bgcolor="rgba(0,0,0,0)", font_color="#cdd6f4")
        st.plotly_chart(fig2, use_container_width=True)

    st.subheader("Top IPs con eventos de alta severidad")
    high = df_all[(df_all["severity"] >= 4) & df_all["src_ip"].notna()]
    if not high.empty:
        top_ips = (high.groupby("src_ip")["severity"]
                   .agg(["count", "max"])
                   .sort_values("count", ascending=False)
                   .head(10)
                   .reset_index())
        top_ips.columns = ["IP", "Eventos", "Severidad max"]
        st.dataframe(top_ips, use_container_width=True)


# ====================== PAGINA 4: ANALIZAR LOG ======================
elif page == "Analizar mi log":
    st.title("Analizar tu propio log")
    uploaded = st.file_uploader("Sube tu auth.log de Linux",
                                type=["log", "txt"])
    contamination = st.slider("Sensibilidad", 0.01, 0.20, 0.05, 0.01)

    if uploaded:
        with st.spinner("Procesando..."):
            try:
                from core.parser import parse_file
                from core.transformer import transform_linux
                from sklearn.ensemble import IsolationForest
                from sklearn.preprocessing import StandardScaler

                tmp = ROOT / "data" / "raw" / "uploaded.log"
                tmp.parent.mkdir(parents=True, exist_ok=True)
                tmp.write_text(uploaded.read().decode(
                    "utf-8", errors="replace"))

                df_raw = parse_file(str(tmp))
                df_t = transform_linux(df_raw)

                st.success(f"{len(df_t)} eventos parseados")
                c1, c2, c3 = st.columns(3)
                c1.metric("Eventos", len(df_t))
                c2.metric("Fallos SSH",
                          int((df_t["event_type"] == "auth_failure").sum()))
                c3.metric("Nocturnos", int(df_t["is_night"].sum()))

                feats = ["hour_of_day", "is_night", "is_weekend",
                         "failed_last_5min", "severity"]
                X = df_t[[c for c in feats if c in df_t.columns]].fillna(0)
                sc = StandardScaler()
                Xs = sc.fit_transform(X)
                md = IsolationForest(
                    contamination=contamination, random_state=42)
                df_t["is_anomaly"] = md.fit_predict(Xs) == -1

                anom = df_t[df_t["is_anomaly"]]
                st.metric("Anomalias detectadas", len(anom),
                          f"{100*len(anom)/max(len(df_t), 1):.1f}%")

                if not anom.empty:
                    show = [c for c in ["timestamp", "event_type", "ip",
                                        "user", "severity", "is_night"]
                            if c in anom.columns]
                    st.dataframe(anom[show].head(50), use_container_width=True)
            except Exception as e:
                st.error(f"Error: {e}")
                import traceback
                st.code(traceback.format_exc())
    else:
        st.info("Sube un archivo auth.log para comenzar el analisis")
