from fastapi import FastAPI
import pandas as pd

from backend.preprocessing import preprocess_alerts
from backend.models import cluster_alerts, detect_anomalies, calculate_risk_score
from backend.mitre_mapping import map_to_mitre
from backend.evaluation import alert_reduction_rate

app = FastAPI(title="AI SIEM Alert Intelligence")

@app.post("/analyze/")
def analyze(alerts: list):
    df = pd.DataFrame(alerts)
    df = preprocess_alerts(df)

    X = df[["severity", "frequency"]]
    df["cluster"] = cluster_alerts(X)
    df["anomaly_raw"] = detect_anomalies(X)
    df["anomaly"] = df["anomaly_raw"].map({1: "Normal", -1: "Suspicious"})

    df["risk_score"] = df.apply(
        lambda x: calculate_risk_score(x["severity"], x["frequency"], x["anomaly_raw"]),
        axis=1
    )

    df["action"] = df["risk_score"].apply(
        lambda x: "SUPPRESS" if x < 20 else "ESCALATE"
    )

    df["mitre"] = df["event_type"].apply(map_to_mitre)

    metrics = {
        "alert_reduction_rate": alert_reduction_rate(
            len(df), len(df[df["action"] == "SUPPRESS"])
        )
    }

    return {
        "alerts": df.to_dict(orient="records"),
        "metrics": metrics
    }
