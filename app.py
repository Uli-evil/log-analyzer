"""
app.py — Dashboard Streamlit del Log Analyzer
===============================================
Demo pública del proyecto. El visitante puede:
  1. Ver KPIs de seguridad en tiempo real
  2. Explorar los ataques detectados por tipo
  3. Ver la línea de tiempo de eventos
  4. Leer las explicaciones generadas por motor de análisis
  5. Subir su propio archivo de log para analizarlo

Uso:
    streamlit run app.py
"""

import sys
import json
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
from datetime import datetime

import streamlit as st

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

# ---------------------------------------------------------------------------
# CONFIGURACIÓN DE LA PÁGINA
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title   = "Log Analyzer — Security Dashboard",
    page_icon    = "🛡️",
    layout       = "wide",
    initial_sidebar_state = "expanded",
)

# Estilo CSS personalizado
st.markdown("""
<style>
    .metric-card {
        background: #1e1e2e;
        border: 1px solid #313244;
        border-radius: 12px;
        padding: 1rem 1.25rem;
        text-align: center;
    }
    .metric-number { font-size: 2rem; font-weight: 600; }
    .metric-label  { font-size: 0.8rem; color: #a6adc8; margin-top: 4px; }
    .attack-badge  {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 500;
    }
    .sev-critica { background:#3d1515; color:#f38ba8; }
    .sev-alta    { background:#3d2a0d; color:#fab387; }
    .sev-media   { background:#3d370d; color:#f9e2af; }
    .sev-baja    { background:#0d3d1a; color:#a6e3a1; }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# FUNCIONES DE DATOS
# ---------------------------------------------------------------------------

DB_PATH = ROOT / "data" / "log_analyzer.db"

@st.cache_data(ttl=30)
def load_stats() -> dict:
    if not DB_PATH.exists():
        return {}
    with sqlite3.connect(str(DB_PATH)) as conn:
        total    = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        anomalies= conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
        critical = conn.execute(
            "SELECT COUNT(*) FROM events WHERE severity=5").fetchone()[0]
        sources  = dict(conn.execute(
            "SELECT source, COUNT(*) FROM events GROUP BY source").fetchall())
        attacks  = dict(conn.execute("""
            SELECT attack_pattern, COUNT(*) FROM anomalies
            WHERE attack_pattern IS NOT NULL
            GROUP BY attack_pattern ORDER BY COUNT(*) DESC
        """).fetchall())
    return {
        "total": total, "anomalies": anomalies,
        "critical": critical, "sources": sources, "attacks": attacks,
    }


@st.cache_data(ttl=30)
def load_events_df() -> pd.DataFrame:
    if not DB_PATH.exists():
        return pd.DataFrame()
    with sqlite3.connect(str(DB_PATH)) as conn:
        return pd.read_sql_query("""
            SELECT timestamp, source, event_type, src_ip,
                   user, severity, is_night, hour_of_day,
                   bytes_total, failed_last_5min, extra
            FROM events
            ORDER BY timestamp
        """, conn)


@st.cache_data(ttl=30)
def load_anomalies_df() -> pd.DataFrame:
    if not DB_PATH.exists():
        return pd.DataFrame()
    with sqlite3.connect(str(DB_PATH)) as conn:
        return pd.read_sql_query("""
            SELECT a.id, a.method, a.score, a.rule_name,
                   a.summary, a.severity as risk_level,
                   a.attack_pattern, a.response_action,
                   e.timestamp, e.source, e.event_type,
                   e.src_ip, e.user, e.severity,
                   e.hour_of_day, e.is_night, e.bytes_total, e.extra
            FROM anomalies a
            JOIN events e ON e.id = a.event_id
            WHERE a.summary IS NOT NULL
            ORDER BY e.severity DESC, a.score ASC
            LIMIT 200
        """, conn)


def severity_badge(sev: str) -> str:
    cls = {"crítica": "sev-critica", "alta": "sev-alta",
           "media": "sev-media",    "baja": "sev-baja"}.get(
               str(sev).lower(), "sev-baja")
    return f'<span class="attack-badge {cls}">{sev}</span>'


# ---------------------------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------------------------

with st.sidebar:
    st.image("https://img.shields.io/badge/Log%20Analyzer-v1.0-blue",
             use_column_width=False)
    st.title("🛡️ Log Analyzer")
    st.caption("Security Anomaly Detection")
    st.divider()

    page = st.radio("Navegación", [
        "📊 Dashboard principal",
        "🔴 Anomalías detectadas",
        "📈 Análisis de eventos",
        "🤖 Explicaciones IA",
        "📁 Analizar mi log",
    ])

    st.divider()
    if DB_PATH.exists():
        stats = load_stats()
        st.metric("Eventos totales", f"{stats.get('total',0):,}")
        st.metric("Anomalías",       f"{stats.get('anomalies',0):,}")
        st.metric("Críticos",        f"{stats.get('critical',0):,}")
    else:
        st.warning("Base de datos no encontrada.\nEjecuta: `python run_etl.py`")


# ---------------------------------------------------------------------------
# PÁGINA 1 — DASHBOARD PRINCIPAL
# ---------------------------------------------------------------------------

if page == "📊 Dashboard principal":
    st.title("📊 Security Operations Dashboard")
    st.caption(f"Log Analyzer · {datetime.now().strftime('%d/%m/%Y %H:%M')}")

    if not DB_PATH.exists():
        st.error("❌ Base de datos no encontrada. Ejecuta `python run_etl.py` primero.")
        st.stop()

    stats = load_stats()
    df    = load_events_df()

    # ── KPIs ──────────────────────────────────────────────────────────────
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric("Total eventos",  f"{stats['total']:,}")
    with col2:
        st.metric("Anomalías",      f"{stats['anomalies']:,}",
                  delta=f"{100*stats['anomalies']/max(stats['total'],1):.1f}% del total",
                  delta_color="inverse")
    with col3:
        st.metric("Críticos (sev 5)", f"{stats['critical']:,}", delta_color="inverse")
    with col4:
        n_ips = df["src_ip"].nunique() if not df.empty else 0
        st.metric("IPs únicas", n_ips)
    with col5:
        n_attacks = len([a for a in stats.get("attacks", {})
                         if a not in ("anomalous_behavior", None)])
        st.metric("Tipos de ataque", n_attacks)

    st.divider()

    # ── Gráficas ──────────────────────────────────────────────────────────
    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader("Eventos por hora del día")
        if not df.empty:
            hourly = df.groupby(["hour_of_day", "source"]).size().reset_index(name="count")
            fig = px.bar(hourly, x="hour_of_day", y="count", color="source",
                         color_discrete_map={
                             "linux":   "#89b4fa",
                             "network": "#a6e3a1",
                             "windows": "#fab387",
                         },
                         labels={"hour_of_day": "Hora", "count": "Eventos",
                                 "source": "Fuente"})
            fig.update_layout(
                plot_bgcolor="rgba(0,0,0,0)",
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#cdd6f4",
            )
            # Zona nocturna sombreada
            fig.add_vrect(x0=22, x1=24, fillcolor="red",
                          opacity=0.08, line_width=0,
                          annotation_text="Zona nocturna",
                          annotation_position="top left")
            fig.add_vrect(x0=0, x1=6, fillcolor="red",
                          opacity=0.08, line_width=0)
            st.plotly_chart(fig, use_container_width=True)

    with col_b:
        st.subheader("Distribución de ataques detectados")
        attacks = stats.get("attacks", {})
        if attacks:
            attack_df = pd.DataFrame(
                list(attacks.items()), columns=["attack", "count"]
            ).sort_values("count", ascending=True).tail(8)
            fig2 = px.bar(attack_df, x="count", y="attack", orientation="h",
                          color="count",
                          color_continuous_scale=["#a6e3a1", "#f9e2af", "#f38ba8"])
            fig2.update_layout(
                plot_bgcolor="rgba(0,0,0,0)",
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#cdd6f4",
                showlegend=False,
            )
            st.plotly_chart(fig2, use_container_width=True)

    # ── Mapa de calor severidad x hora ────────────────────────────────────
    st.subheader("Mapa de calor — Severidad por hora")
    if not df.empty:
        heat = df.groupby(["hour_of_day", "severity"]).size().unstack(fill_value=0)
        fig3 = px.imshow(
            heat.T,
            labels=dict(x="Hora del día", y="Severidad", color="Eventos"),
            color_continuous_scale=["#1e1e2e", "#f9e2af", "#f38ba8"],
            aspect="auto",
        )
        fig3.update_layout(
            plot_bgcolor="rgba(0,0,0,0)",
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="#cdd6f4",
        )
        st.plotly_chart(fig3, use_container_width=True)


# ---------------------------------------------------------------------------
# PÁGINA 2 — ANOMALÍAS DETECTADAS
# ---------------------------------------------------------------------------

elif page == "🔴 Anomalías detectadas":
    st.title("🔴 Anomalías Detectadas")

    df_a = load_anomalies_df()

    if df_a.empty:
        st.info("No hay anomalías explicadas aún. Ejecuta: `python core/ai_engine.py`")
        st.stop()

    # Filtros
    col1, col2, col3 = st.columns(3)
    with col1:
        fuentes = ["Todas"] + list(df_a["source"].unique())
        fuente  = st.selectbox("Fuente", fuentes)
    with col2:
        sevs    = ["Todas"] + list(df_a["risk_level"].dropna().unique())
        sev_f   = st.selectbox("Severidad", sevs)
    with col3:
        methods = ["Todos"] + list(df_a["method"].unique())
        method  = st.selectbox("Método de detección", methods)

    # Aplicar filtros
    filtered = df_a.copy()
    if fuente  != "Todas": filtered = filtered[filtered["source"] == fuente]
    if sev_f   != "Todas": filtered = filtered[filtered["risk_level"] == sev_f]
    if method  != "Todos": filtered = filtered[filtered["method"] == method]

    st.caption(f"Mostrando {len(filtered):,} anomalías")

    # Tabla
    cols_show = ["timestamp", "source", "event_type", "src_ip",
                 "user", "risk_level", "attack_pattern", "method"]
    available = [c for c in cols_show if c in filtered.columns]
    st.dataframe(
        filtered[available].rename(columns={
            "timestamp":       "Timestamp",
            "source":          "Fuente",
            "event_type":      "Tipo evento",
            "src_ip":          "IP origen",
            "user":            "Usuario",
            "risk_level":"Severidad",
            "attack_pattern":   "Tipo de ataque",
            "method":          "Método detección",
        }),
        use_container_width=True,
        height=400,
    )

    # Detalle al hacer clic
    st.subheader("Detalle de anomalía")
    if not filtered.empty:
        idx = st.number_input("Número de fila (0 = primera)",
                              min_value=0, max_value=len(filtered)-1, value=0)
        row = filtered.iloc[int(idx)]

        col_l, col_r = st.columns(2)
        with col_l:
            st.markdown(f"**Fuente:** `{row.get('source','')}`")
            st.markdown(f"**Evento:** `{row.get('event_type','')}`")
            st.markdown(f"**IP origen:** `{row.get('src_ip','N/A')}`")
            st.markdown(f"**Usuario:** `{row.get('user','N/A')}`")
            st.markdown(f"**Hora:** `{row.get('hour_of_day','?')}:00`"
                        + (" 🌙 Nocturno" if row.get("is_night") else ""))
        with col_r:
            sev = str(row.get("risk_level","baja"))
            st.markdown(f"**Severidad:** {severity_badge(sev)}",
                        unsafe_allow_html=True)
            st.markdown(f"**Ataque:** `{row.get('attack_pattern','N/A')}`")
            st.markdown(f"**Método:** `{row.get('method','N/A')}`")
            if row.get("score"):
                st.markdown(f"**Score ML:** `{row['score']:.3f}`")

        if row.get("summary"):
            st.info(f"💬 **Explicación (Claude):** {row['summary']}")
        if row.get("response_action"):
            st.warning(f"⚡ **Acción recomendada:** {row['response_action']}")


# ---------------------------------------------------------------------------
# PÁGINA 3 — ANÁLISIS DE EVENTOS
# ---------------------------------------------------------------------------

elif page == "📈 Análisis de eventos":
    st.title("📈 Análisis de Eventos")

    df = load_events_df()
    if df.empty:
        st.error("No hay datos. Ejecuta `python run_etl.py`")
        st.stop()

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Eventos por fuente")
        src_counts = df["source"].value_counts().reset_index()
        src_counts.columns = ["Fuente", "Eventos"]
        fig = px.pie(src_counts, values="Eventos", names="Fuente",
                     color_discrete_map={
                         "linux":   "#89b4fa",
                         "network": "#a6e3a1",
                         "windows": "#fab387",
                     })
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#cdd6f4")
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Top 10 tipos de evento")
        top_events = df["event_type"].value_counts().head(10).reset_index()
        top_events.columns = ["Tipo", "Conteo"]
        fig2 = px.bar(top_events, x="Conteo", y="Tipo", orientation="h",
                      color="Conteo",
                      color_continuous_scale=["#89b4fa", "#f38ba8"])
        fig2.update_layout(
            plot_bgcolor="rgba(0,0,0,0)",
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="#cdd6f4",
        )
        st.plotly_chart(fig2, use_container_width=True)

    st.subheader("Top IPs con más eventos de alta severidad")
    high_sev = df[df["severity"] >= 4]
    if not high_sev.empty and "src_ip" in high_sev.columns:
        top_ips = (
            high_sev[high_sev["src_ip"].notna()]
            .groupby("src_ip")
            .agg(total=("severity","count"), max_sev=("severity","max"))
            .sort_values("total", ascending=False)
            .head(10)
            .reset_index()
        )
        st.dataframe(top_ips.rename(columns={
            "src_ip":"IP", "total":"Eventos altos", "max_sev":"Severidad max"
        }), use_container_width=True)


# ---------------------------------------------------------------------------
# PÁGINA 4 — EXPLICACIONES IA
# ---------------------------------------------------------------------------

elif page == "🤖 Explicaciones IA":
    st.title("🤖 Explicaciones generadas por motor de análisis")
    st.caption("Cada anomalía analizada por un analista SOC virtual")

    df_a = load_anomalies_df()
    explained = df_a[df_a["summary"].notna()] if not df_a.empty else pd.DataFrame()

    if explained.empty:
        st.info("Aún no hay explicaciones. Ejecuta: `python core/ai_engine.py --limit 20`")
        st.stop()

    st.metric("Anomalías explicadas", len(explained))

    for _, row in explained.head(20).iterrows():
        sev = str(row.get("risk_level", "baja")).lower()
        icon = {"crítica": "🔴", "alta": "🟠", "media": "🟡", "baja": "🟢"}.get(sev, "⚪")

        with st.expander(
            f"{icon} [{row.get('source','').upper()}] "
            f"{row.get('event_type','')} — "
            f"{row.get('attack_pattern','')} — "
            f"IP: {row.get('src_ip','N/A')}"
        ):
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**Severidad:** {severity_badge(sev)}",
                            unsafe_allow_html=True)
                st.markdown(f"**Tipo de ataque:** `{row.get('attack_pattern','N/A')}`")
                st.markdown(f"**Método:** `{row.get('method','N/A')}`")
                if row.get("score"):
                    st.markdown(f"**Score ML:** `{row['score']:.3f}`")
            with col2:
                st.markdown(f"**Fuente:** `{row.get('source','N/A')}`")
                st.markdown(f"**Usuario:** `{row.get('user','N/A')}`")
                st.markdown(f"**Hora:** `{row.get('hour_of_day','?')}:00`")

            if row.get("summary"):
                st.info(f"💬 {row['summary']}")
            if row.get("response_action"):
                st.warning(f"⚡ **Acción:** {row['response_action']}")


# ---------------------------------------------------------------------------
# PÁGINA 5 — ANALIZAR MI LOG
# ---------------------------------------------------------------------------

elif page == "📁 Analizar mi log":
    st.title("📁 Analizar tu propio archivo de log")
    st.caption("Sube un auth.log de Linux y ve las anomalías detectadas en tiempo real")

    uploaded = st.file_uploader(
        "Sube tu archivo auth.log",
        type=["log", "txt"],
        help="Archivo /var/log/auth.log de Linux"
    )

    col1, col2 = st.columns(2)
    with col1:
        n_lines = st.slider("Máximo de líneas a procesar", 100, 5000, 1000)
    with col2:
        contamination = st.slider("Sensibilidad de detección",
                                   0.01, 0.20, 0.05, 0.01,
                                   help="Fracción esperada de anomalías")

    if uploaded:
        with st.spinner("Procesando log..."):
            try:
                from core.parser      import parse_file
                from core.transformer import transform_linux
                from core.detector    import AnomalyDetector

                # Guardar temporalmente
                tmp_path = ROOT / "data" / "raw" / "uploaded_auth.log"
                content  = uploaded.read().decode("utf-8", errors="replace")
                lines    = content.splitlines()[:n_lines]
                tmp_path.write_text("\n".join(lines))

                # Parsear
                df_raw = parse_file(str(tmp_path))
                st.success(f"✓ {len(df_raw)} eventos parseados")

                # Transformar
                df_t = transform_linux(df_raw)

                # Mostrar distribución
                col_a, col_b, col_c = st.columns(3)
                with col_a:
                    st.metric("Eventos", len(df_t))
                with col_b:
                    fails = int((df_t["event_type"] == "auth_failure").sum())
                    st.metric("Fallos de autenticación", fails)
                with col_c:
                    night = int(df_t["is_night"].sum())
                    st.metric("Eventos nocturnos", night)

                # Gráfica rápida
                st.subheader("Eventos por hora")
                hourly = df_t.groupby("hour_of_day").size().reset_index(name="count")
                fig = px.bar(hourly, x="hour_of_day", y="count",
                             color="count",
                             color_continuous_scale=["#a6e3a1","#f38ba8"])
                fig.update_layout(
                    plot_bgcolor="rgba(0,0,0,0)",
                    paper_bgcolor="rgba(0,0,0,0)",
                    font_color="#cdd6f4",
                )
                st.plotly_chart(fig, use_container_width=True)

                # Detección rápida con Isolation Forest
                st.subheader("🔍 Anomalías detectadas")
                from sklearn.ensemble import IsolationForest
                from sklearn.preprocessing import StandardScaler

                feature_cols = ["hour_of_day","is_night","is_weekend",
                                "failed_last_5min","severity"]
                X = df_t[[c for c in feature_cols if c in df_t.columns]].fillna(0)
                scaler = StandardScaler()
                X_sc   = scaler.fit_transform(X)

                model  = IsolationForest(contamination=contamination,
                                         random_state=42)
                df_t["anomaly_score"] = model.fit_predict(X_sc)
                df_t["score_val"]     = model.score_samples(X_sc)
                df_t["is_anomaly"]    = df_t["anomaly_score"] == -1

                anomalies = df_t[df_t["is_anomaly"]].sort_values("score_val")

                st.metric("Anomalías detectadas",
                           len(anomalies),
                           f"{100*len(anomalies)/len(df_t):.1f}% del total")

                if not anomalies.empty:
                    show_cols = [c for c in
                                 ["timestamp","event_type","ip","user",
                                  "severity","is_night","failed_last_5min",
                                  "score_val"] if c in anomalies.columns]
                    st.dataframe(
                        anomalies[show_cols].head(50).rename(columns={
                            "timestamp":"Timestamp",
                            "event_type":"Tipo evento",
                            "ip":"IP origen",
                            "user":"Usuario",
                            "severity":"Severidad",
                            "is_night":"Nocturno",
                            "failed_last_5min":"Fallos 5min",
                            "score_val":"Score anomalía",
                        }),
                        use_container_width=True,
                    )
                else:
                    st.success("No se detectaron anomalías significativas.")

            except Exception as e:
                st.error(f"Error procesando el archivo: {e}")
                st.exception(e)
    else:
        st.info("👆 Sube un archivo auth.log para comenzar el análisis")
        st.markdown("""
        **¿No tienes un log real?**

        Genera uno de prueba con anomalías incluidas:
        ```powershell
        python scripts/generate_auth_log.py --lines 500
        # Archivo generado en: data/raw/sample_auth.log
        ```
        """)
