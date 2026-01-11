# import streamlit as st
# import pandas as pd
# import requests
# import plotly.express as px
# import sys
# import os

# # Fix for relative imports - add project root to path
# sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# # Try to import if available, otherwise use direct calculation
# try:
#     from evaluation import alert_reduction_rate
#     HAS_EVAL = True
# except ImportError:
#     HAS_EVAL = False
#     def alert_reduction_rate(total, suppressed):
#         return (suppressed / total * 100) if total > 0 else 0

# st.set_page_config(page_title="SIEM Alert Dashboard", layout="wide")

# st.title("🛡️ AI SIEM Alert Noise Reduction Dashboard")

# # File upload
# uploaded_file = st.file_uploader("📁 Upload alerts CSV", type="csv")

# if uploaded_file:
#     df = pd.read_csv(uploaded_file)
#     st.subheader("📊 Raw Alerts")
#     st.dataframe(df.head(10), use_container_width=True)

#     if st.button("🚀 Analyze & Reduce Noise", type="primary"):
#         with st.spinner("Running ML clustering, anomaly detection, and risk scoring..."):
#             try:
#                 response = requests.post(
#                     "http://127.0.0.1:8000/analyze",  # Fixed endpoint (no trailing slash)
#                     json=df.to_dict(orient="records"),
#                     timeout=30
#                 )
#                 if response.status_code != 200:
#                     raise Exception(f"Backend returned {response.status_code}")
                
#                 result = response.json()
#                 result_df = pd.DataFrame(result["alerts"])
                
#                 col1, col2 = st.columns(2)
                
#                 with col1:
#                     st.subheader("📈 Processed Alerts")
#                     st.dataframe(result_df, use_container_width=True)
                
#                 with col2:
#                     st.subheader("📊 Key Metrics")
#                     total = result["metrics"]["totalalerts"]
#                     suppressed = result["metrics"]["suppressed"]
#                     reduction = result["metrics"]["reductionrate"]
                    
#                     col1m, col2m, col3m = st.columns(3)
#                     col1m.metric("Total Alerts", total)
#                     col2m.metric("Suppressed", suppressed)
#                     col3m.metric("Reduction Rate", f"{reduction:.1f}%")
        
#                 # Risk score visualization - match backend field names
#                 fig = px.scatter(
#                     result_df,
#                     x="severity",
#                     y="frequency",
#                     size="riskscore",  # Fixed field name
#                     color="action",
#                     hover_data=["eventtype", "mitretactic", "bestmodel"],  # Backend fields
#                     title="🎯 Alert Risk Analysis"
#                 )
#                 st.plotly_chart(fig, use_container_width=True)
                
#                 st.success(f"🎉 {reduction:.1f}% noise reduction achieved!")
                
#             except Exception as e:
#                 st.error(f"❌ Analysis failed: {str(e)}")
#                 st.info("💡 Make sure FastAPI backend is running: `uvicorn main:app --reload`")

# st.info("👆 Upload CSV → Click Analyze → See noise reduction in action!")
import streamlit as st
import pandas as pd
import requests
import plotly.express as px

st.set_page_config(page_title="SIEM Dashboard", layout="wide")
st.title("🛡️ AI SIEM Alert Noise Reduction")

uploaded_file = st.file_uploader("📁 Upload CSV", type="csv", key="uploader")

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    st.subheader("📊 Raw Alerts")
    st.dataframe(df.head(10), width="stretch")

    if st.button("🚀 Analyze", type="primary", key="analyze"):
        with st.spinner("Analyzing with 11 ML models..."):
            try:
                # Your exact backend endpoint
                resp = requests.post(
                    "http://127.0.0.1:8000/analyze/",
                    json=df.to_dict(orient="records"),
                    timeout=60
                )
                
                result = resp.json()
                result_df = pd.DataFrame(result["alerts"])
                
                # ✅ SNAKE CASE (matches YOUR backend)
                metrics = result["metrics"]
                
                col1, col2 = st.columns(2)
                with col1:
                    st.subheader("✅ Processed Alerts")
                    st.dataframe(result_df, width="stretch")
                
                with col2:
                    st.subheader("📊 Key Metrics")
                    metrics = result["metrics"]
                    c1, c2, c3, c4 = st.columns(4)
                    # ✅ CAMEL CASE (matches your backend)
                    reduction = metrics.get("reductionrate", metrics.get("reduction_rate", 0))
                    total = metrics.get("totalalerts", metrics.get("total_alerts", 0))
                    suppressed = metrics.get("suppressed", 0)
                    top_model = metrics.get("topmodel", metrics.get("top_model", "N/A"))

                    c1.metric("Total Alerts", total)
                    c2.metric("Suppressed", suppressed)
                    c3.metric("Reduction Rate", f"{reduction:.1f}%")
                    c4.metric("🏆 Best Model", top_model)


                # Risk scatter plot
                fig = px.scatter(
                    result_df,
                    x="frequency",
                    y="risk_score",
                    size="severity",
                    color="action",
                    hover_data=["event_type", "mitre_tactic", "best_model"],
                    title="🎯 Alert Risk Analysis (Red=ESCALATE, Blue=SUPPRESS)"
                )
                st.plotly_chart(fig, width="stretch")


                st.success(f"🎉 {reduction:.1f}% noise reduced!")

            except KeyError as e:
                st.error(f"❌ Missing key: {e}")
                st.info("Expected backend format confirmed by test_backend.py")
            except Exception as e:
                st.error(f"❌ {str(e)}")

st.markdown("""
### 🚀 Production Demo Ready
- Backend: `uvicorn main:app --reload`
- Dashboard: `streamlit run dashboard.py`
- CSV: `event_type`, `severity`, `frequency` columns
""")
