"""
app_cloud.py - Log Analyzer para Streamlit Cloud
Lee SQLite directamente. Se auto-inicializa si no hay BD.
Uso en Streamlit Cloud: Main file = app_cloud.py
"""
import sys
import sqlite3
import pandas as pd
import plotly.express as px
from pathlib import Path
from datetime import datetime

import streamlit as st

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

DB = ROOT / "data" / "log_analyzer.db"

st.set_page_config(page_title="Log Analyzer", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")

COLORS = {"linux":"#89b4fa","network":"#a6e3a1","windows":"#fab387"}


@st.cache_resource
def init_database():
    """Genera la BD al arrancar si no existe. Solo corre una vez."""
    if DB.exists():
        conn = sqlite3.connect(str(DB))
        n = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        conn.close()
        if n > 0:
            return True

    with st.spinner("Inicializando base de datos de seguridad..."):
        try:
            import pandas as pd
            from core.parser      import parse_file
            from core.transformer import transform_linux, transform_network, transform_windows, unify
            from core.loader      import Loader
            from core.detector    import AnomalyDetector

            # Generar datos si no existen
            auth = ROOT / "data" / "raw" / "sample_auth.log"
            net  = ROOT / "data" / "raw" / "network_traffic.csv"
            win  = ROOT / "data" / "raw" / "windows_events.csv"

            if not auth.exists():
                from scripts.generate_auth_log     import generate_log
                from scripts.generate_network_csv  import generate_csv
                from scripts.generate_windows_events import generate_events
                (ROOT/"data"/"raw").mkdir(parents=True, exist_ok=True)
                lines = generate_log(500)
                auth.write_text("\n".join(lines))
                generate_csv(1000).to_csv(net, index=False)
                generate_events(800).to_csv(win, index=False)

            dfs = []
            if auth.exists(): dfs.append(transform_linux(parse_file(str(auth))))
            if net.exists():  dfs.append(transform_network(pd.read_csv(str(net))))
            if win.exists():  dfs.append(transform_windows(pd.read_csv(str(win))))

            if not dfs:
                return False

            df_all = unify(dfs)
            loader = Loader(str(DB))
            loader.init_db()
            loader.insert_events(df_all)

            det    = AnomalyDetector(db_path=str(DB))
            scored = det.detect_ml(df_all)
            rules  = det.detect_rules()
            det.save_anomalies(scored, rules)
            return True
        except Exception as e:
            st.error(f"Error al inicializar: {e}")
            return False


def get_conn():
    return sqlite3.connect(str(DB))


@st.cache_data(ttl=60)
def load_stats():
    conn = get_conn()
    total    = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    anomalies= conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
    critical = conn.execute("SELECT COUNT(*) FROM events WHERE severity=5").fetchone()[0]
    by_src   = dict(conn.execute("SELECT source,COUNT(*) FROM events GROUP BY source").fetchall())
    attacks  = dict(conn.execute("SELECT attack_pattern,COUNT(*) FROM anomalies WHERE attack_pattern IS NOT NULL GROUP BY attack_pattern ORDER BY COUNT(*) DESC LIMIT 8").fetchall())
    conn.close()
    return {"total":total,"anomalies":anomalies,"critical":critical,
            "by_source":by_src,"attacks":attacks}


@st.cache_data(ttl=60)
def load_events():
    conn = get_conn()
    df = pd.read_sql_query(
        "SELECT timestamp,source,event_type,src_ip,user,severity,hour_of_day,is_night,bytes_total FROM events ORDER BY timestamp",
        conn
    )
    conn.close()
    return df


@st.cache_data(ttl=60)
def load_anomalies():
    conn = get_conn()
    df = pd.read_sql_query("""
        SELECT a.id, a.method, a.score, a.severity as risk_level,
               a.attack_pattern, a.summary, a.response_action,
               e.timestamp, e.source, e.event_type,
               e.src_ip, e.user, e.severity
        FROM anomalies a JOIN events e ON e.id=a.event_id
        WHERE a.summary IS NOT NULL
        ORDER BY e.severity DESC, a.score ASC
        LIMIT 200
    """, conn)
    conn.close()
    return df


# ---- SIDEBAR ----
with st.sidebar:
    st.title("🛡️ Log Analyzer")
    st.caption("Security Anomaly Detection")
    st.divider()
    page = st.radio("Navegacion", [
        "📊 Dashboard",
        "🔴 Anomalias detectadas",
        "📈 Analisis de eventos",
        "📁 Analizar mi log",
    ])

# ---- INICIALIZAR ----
ok = init_database()
if not ok:
    st.error("No se pudo inicializar la base de datos.")
    st.stop()

# ---- PAGINA 1: DASHBOARD ----
if page == "📊 Dashboard":
    st.title("📊 Security Operations Dashboard")
    st.caption(f"{datetime.now().strftime('%d/%m/%Y %H:%M')}")

    s = load_stats()
    c1,c2,c3,c4,c5 = st.columns(5)
    c1.metric("Total eventos",  f"{s['total']:,}")
    c2.metric("Anomalias",      f"{s['anomalies']:,}",
              delta=f"{100*s['anomalies']/max(s['total'],1):.1f}%", delta_color="inverse")
    c3.metric("Criticos",       f"{s['critical']:,}", delta_color="inverse")
    c4.metric("Fuentes",        len(s['by_source']))
    c5.metric("Tipos ataque",   len(s['attacks']))

    st.divider()
    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader("Eventos por fuente")
        if s["by_source"]:
            df_src = pd.DataFrame(list(s["by_source"].items()), columns=["Fuente","Eventos"])
            fig = px.pie(df_src, values="Eventos", names="Fuente",
                         color="Fuente", color_discrete_map=COLORS)
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#cdd6f4")
            st.plotly_chart(fig, use_container_width=True)

    with col_b:
        st.subheader("Top tipos de ataque")
        if s["attacks"]:
            df_a = pd.DataFrame(list(s["attacks"].items()), columns=["Ataque","Conteo"]).sort_values("Conteo")
            fig2 = px.bar(df_a, x="Conteo", y="Ataque", orientation="h",
                          color="Conteo", color_continuous_scale=["#a6e3a1","#fab387","#f38ba8"])
            fig2.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                               font_color="#cdd6f4", showlegend=False)
            st.plotly_chart(fig2, use_container_width=True)

    df = load_events()
    if not df.empty and "hour_of_day" in df.columns:
        st.subheader("Mapa de calor — Actividad por hora y severidad")
        heat = df.groupby(["hour_of_day","severity"]).size().unstack(fill_value=0)
        fig3 = px.imshow(heat.T, labels=dict(x="Hora",y="Severidad",color="Eventos"),
                         color_continuous_scale=["#1e1e2e","#f9e2af","#f38ba8"], aspect="auto")
        fig3.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#cdd6f4")
        st.plotly_chart(fig3, use_container_width=True)

    st.subheader("Eventos en el tiempo")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    fig4 = px.scatter(df.sort_values("timestamp"), x="timestamp", y="severity",
                      color="source", color_discrete_map=COLORS, opacity=0.6,
                      labels={"timestamp":"Hora","severity":"Severidad","source":"Fuente"})
    fig4.add_hline(y=4, line_dash="dash", line_color="#f38ba8", annotation_text="Umbral alto")
    fig4.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="#cdd6f4")
    st.plotly_chart(fig4, use_container_width=True)

# ---- PAGINA 2: ANOMALIAS ----
elif page == "🔴 Anomalias detectadas":
    st.title("🔴 Anomalias Detectadas")
    df_a = load_anomalies()

    if df_a.empty:
        st.info("Sin anomalias analizadas todavia.")
        st.stop()

    c1,c2 = st.columns(2)
    fuente  = c1.selectbox("Fuente", ["Todas","linux","network","windows"])
    min_sev = c2.selectbox("Severidad minima", [1,2,3,4,5], index=2)

    filtered = df_a.copy()
    if fuente != "Todas":
        filtered = filtered[filtered["source"]==fuente]
    filtered = filtered[filtered["severity"]>=min_sev]

    st.caption(f"{len(filtered)} anomalias")
    show = [c for c in ["timestamp","source","event_type","src_ip","user",
                         "severity","risk_level","attack_pattern"] if c in filtered.columns]
    st.dataframe(filtered[show], use_container_width=True, height=350)

    if not filtered.empty:
        st.subheader("Detalle")
        idx = st.number_input("Fila", 0, max(len(filtered)-1,0), 0)
        row = filtered.iloc[int(idx)]
        cl, cr = st.columns(2)
        cl.markdown(f"**Fuente:** `{row.get('source','N/A')}`")
        cl.markdown(f"**Evento:** `{row.get('event_type','N/A')}`")
        cl.markdown(f"**IP:** `{row.get('src_ip','N/A')}`")
        risk = str(row.get("risk_level","bajo")).lower()
        color = {"critico":"#f38ba8","alto":"#fab387","medio":"#f9e2af"}.get(risk,"#a6e3a1")
        cr.markdown(f"**Riesgo:** <span style='color:{color};font-weight:700'>{risk.upper()}</span>",
                    unsafe_allow_html=True)
        cr.markdown(f"**Patron:** `{row.get('attack_pattern','N/A')}`")
        cr.markdown(f"**Metodo:** `{row.get('method','N/A')}`")
        if row.get("summary"):
            st.info(f"Analisis: {row['summary']}")
        if row.get("response_action"):
            st.warning(f"Accion: {row['response_action']}")

# ---- PAGINA 3: ANALISIS ----
elif page == "📈 Analisis de eventos":
    st.title("📈 Analisis de Eventos")
    df = load_events()
    if df.empty:
        st.info("Sin datos.")
        st.stop()

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Distribucion por fuente")
        fig = px.pie(df, names="source", color="source", color_discrete_map=COLORS)
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#cdd6f4")
        st.plotly_chart(fig, use_container_width=True)
    with col2:
        st.subheader("Top tipos de evento")
        top = df["event_type"].value_counts().head(10).reset_index()
        top.columns = ["Tipo","Conteo"]
        fig2 = px.bar(top.sort_values("Conteo"), x="Conteo", y="Tipo", orientation="h",
                      color="Conteo", color_continuous_scale=["#89b4fa","#f38ba8"])
        fig2.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                           font_color="#cdd6f4")
        st.plotly_chart(fig2, use_container_width=True)

    st.subheader("Top IPs de alta severidad")
    high = df[df["severity"]>=4]
    if not high.empty and "src_ip" in high.columns:
        top_ips = high[high["src_ip"].notna()].groupby("src_ip")["severity"].agg(["count","max"]).sort_values("count",ascending=False).head(10).reset_index()
        top_ips.columns = ["IP","Eventos","Severidad max"]
        st.dataframe(top_ips, use_container_width=True)

# ---- PAGINA 4: ANALIZAR LOG ----
elif page == "📁 Analizar mi log":
    st.title("📁 Analizar tu propio log")
    uploaded = st.file_uploader("Sube tu auth.log de Linux", type=["log","txt"])
    contamination = st.slider("Sensibilidad", 0.01, 0.20, 0.05, 0.01)

    if uploaded:
        with st.spinner("Procesando..."):
            try:
                from core.parser      import parse_file
                from core.transformer import transform_linux
                from sklearn.ensemble import IsolationForest
                from sklearn.preprocessing import StandardScaler

                tmp = ROOT / "data" / "raw" / "uploaded.log"
                tmp.write_text(uploaded.read().decode("utf-8", errors="replace"))
                df_raw = parse_file(str(tmp))
                df_t   = transform_linux(df_raw)

                st.success(f"{len(df_t)} eventos parseados")
                c1,c2,c3 = st.columns(3)
                c1.metric("Eventos", len(df_t))
                c2.metric("Fallos SSH", int((df_t["event_type"]=="auth_failure").sum()))
                c3.metric("Nocturnos", int(df_t["is_night"].sum()))

                feats = ["hour_of_day","is_night","is_weekend","failed_last_5min","severity"]
                X = df_t[[c for c in feats if c in df_t.columns]].fillna(0)
                sc = StandardScaler()
                Xs = sc.fit_transform(X)
                model = IsolationForest(contamination=contamination, random_state=42)
                df_t["score"] = model.fit_predict(Xs)
                df_t["is_anomaly"] = df_t["score"] == -1

                anom = df_t[df_t["is_anomaly"]]
                st.metric("Anomalias detectadas", len(anom),
                          f"{100*len(anom)/len(df_t):.1f}% del total")
                if not anom.empty:
                    show = [c for c in ["timestamp","event_type","ip","user","severity","is_night"] if c in anom.columns]
                    st.dataframe(anom[show].head(50), use_container_width=True)
            except Exception as e:
                st.error(f"Error: {e}")
    else:
        st.info("Sube un archivo auth.log para comenzar el analisis")
