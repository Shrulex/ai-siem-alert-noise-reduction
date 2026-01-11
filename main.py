from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel          # ← ADD THIS
from typing import List                 # ← ADD THIS
import pandas as pd

from preprocessing import preprocess_alerts
from models import cluster_alerts, detect_anomalies, calculate_risk_score
from mitre_mapping import map_to_mitre
from evaluation import alert_reduction_rate

app = FastAPI(title="AI SIEM Alert Noise Reduction")

# Enable CORS for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Alert(BaseModel):                    # ← ADD THIS
    event_type: str = "Unknown"
    severity: int = 1
    frequency: int = 1

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/analyze/")
def analyze(alerts: List[Alert]):          # ← CHANGE: List[Alert]
    # Convert Pydantic models to dicts for pandas
    data = [{"event_type": a.event_type, "severity": a.severity, "frequency": a.frequency} for a in alerts]
    df = pd.DataFrame(data)
    df = preprocess_alerts(df)

    X = df[["severity", "frequency"]]
    df["cluster"] = cluster_alerts(X)
    df["anomaly_raw"] = detect_anomalies(X)
    df["anomaly"] = df["anomaly_raw"].map({1: "Normal", -1: "Suspicious"})

    df["risk_score"] = df.apply(
        lambda x: calculate_risk_score(x["severity"], x["frequency"], x["anomaly_raw"]),
        axis=1,
    )

    df["action"] = df["risk_score"].apply(
        lambda x: "SUPPRESS" if x < 20 else "ESCALATE"
    )

    df["mitre"] = df["event_type"].apply(map_to_mitre)

    suppressed = len(df[df["action"] == "SUPPRESS"])
    metrics = {
        "total_alerts": len(df),
        "suppressed": suppressed,
        "alert_reduction_rate": alert_reduction_rate(len(df), suppressed)
    }

    return {
        "alerts": df.to_dict(orient="records"),
        "metrics": metrics,
    }
