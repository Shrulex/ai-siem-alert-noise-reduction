import streamlit as st
import pandas as pd
import requests
import plotly.express as px

st.set_page_config(page_title="SIEM Alert Dashboard", layout="wide")

st.title("🛡️ AI SIEM Alert Noise Reduction Dashboard")

# File upload
uploaded_file = st.file_uploader("📁 Upload alerts CSV", type="csv")

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.subheader("📊 Raw Alerts")
    st.dataframe(df.head(10), use_container_width=True)

    if st.button("🚀 Analyze & Reduce Noise", type="primary"):
        with st.spinner("Running ML clustering, anomaly detection, and risk scoring..."):
            try:
                response = requests.post(
                    "http://127.0.0.1:8000/analyze/",
                    json=df.to_dict(orient="records"),
                    timeout=30
                )
                result = response.json()
                
                result_df = pd.DataFrame(result["alerts"])
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("📈 Processed Alerts")
                    st.dataframe(result_df, use_container_width=True)
                
                with col2:
                    st.subheader("📊 Key Metrics")
                    col1m, col2m, col3m = st.columns(3)
                    col1m.metric("Total Alerts", result["metrics"]["total_alerts"])
                    col2m.metric("Suppressed", result["metrics"]["suppressed"])
                    col3m.metric("Reduction Rate", f"{result['metrics']['alert_reduction_rate']}%")
                
                # Risk score visualization
                fig = px.scatter(
                    result_df,
                    x="severity",
                    y="frequency",
                    size="risk_score",
                    color="action",
                    hover_data=["event_type", "anomaly", "risk_score"],
                    title="Alert Risk Analysis"
                )
                st.plotly_chart(fig, use_container_width=True)
                
            except Exception as e:
                st.error(f"❌ Analysis failed: {str(e)}")
                st.info("💡 Make sure FastAPI backend is running: `uvicorn main:app --reload`")

st.info("👆 Upload CSV → Click Analyze → See noise reduction in action!")
