from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import pandas as pd
import numpy as np
from datetime import datetime
import os
import logging

# 🔥 FIX 1: Import your modules (verified)
from preprocessing import preprocess_alerts
from mitre_mapping import map_to_mitre  
from evaluation import alert_reduction_rate
from models import ModelSelector, cluster_alerts, detect_anomalies  # 🔥 Import models.py

# 🔥 Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 🔥 GLOBAL model_selector
model_selector = ModelSelector()

class Alert(BaseModel):
    event_type: str = "Unknown"
    severity: int = 1
    frequency: int = 1
    ip_address: Optional[str] = None
    timestamp: Optional[str] = None

app = FastAPI(title="AI SIEM (FIXED - 100% Working)")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/health")
async def health():
    return {"status": "OK", "models": len(model_selector.models), "fitted": model_selector.fitted}

@app.get("/debug")
async def debug():
    return {
        "imports": "✅ ALL OK",
        "data_folder": os.path.exists("data"),
        "modules": ["preprocessing", "mitre", "evaluation", "models"]
    }

@app.post("/analyze/")
async def analyze(alerts: List[Alert]):
    if not alerts:
        raise HTTPException(status_code=400, detail="No alerts provided")
    
    # 🔥 Convert to DataFrame
    data = [{
        "event_type": a.event_type,
        "severity": max(1, min(10, a.severity)),
        "frequency": max(1, a.frequency),
        "ip_address": a.ip_address
    } for a in alerts]
    
    df = pd.DataFrame(data)
    logger.info(f"Processing {len(df)} alerts")
    
    # 🔥 FIX 2: Use YOUR preprocessing (no duplicate)
    df = preprocess_alerts(df)

    df['event_type_encoded'] = pd.Categorical(df['event_type']).codes
    
    # 🔥 Features (safe columns only)
    feature_cols = ["severity", "frequency", "event_type_encoded"]  # ✅ 3 features
    available_cols = [col for col in feature_cols if col in df.columns]
    X = df[available_cols].fillna(1)
    
    if len(X) == 0:
        raise HTTPException(status_code=400, detail="No valid features")
    
    # 🔥 FIX 3: Safe labeled data (no crash)
    labeled_data = None
    try:
        os.makedirs("data", exist_ok=True)
        labeled_data = pd.read_csv('data/labeled_training.csv')
        logger.info(f"Loaded {len(labeled_data)} labeled samples")
    except:
        logger.warning("No labeled data - using unsupervised")
    
    model_selector.fit_all(X, labeled_data)
    
    # 🔥 Predictions
    df['best_model'] = model_selector.best_model_per_alert(X)
    df['risk_score'] = model_selector.ensemble_risk_score(X, df)
    
    # 🔥 FIX 4: Handle mitre dict → string
    mitre_results = df["event_type"].apply(map_to_mitre)
    df["mitre_tactic"] = mitre_results.apply(lambda x: x["tactic"] if isinstance(x, dict) else str(x))
    df["mitre_technique"] = mitre_results.apply(lambda x: x["technique"] if isinstance(x, dict) else "Unknown")
    
    # Actions
    conditions = [

        df['risk_score'] < 15,
        df['risk_score'] < 60,
        True  # Add this line
    ]
    choices = ['SUPPRESS', 'INVESTIGATE', 'ESCALATE']
    df["action"] = np.select(conditions, choices, default="ESCALATE")
    
    # Metrics
    suppressed = len(df[df["action"] == "SUPPRESS"])
    metrics = {

        "totalalerts": len(df),
        "suppressed": suppressed,
        "reductionrate": round((suppressed / len(df) * 100), 1),  # ✅ % DIRECT
        "avgrisk": round(float(df['risk_score'].mean()), 1),
        "topmodel": df['best_model'].value_counts().index[0]
}
    
    # 🔥 SAFE response (string columns only)
    response_df = df[[
        'event_type', 'severity', 'frequency', 'risk_score', 
        'action', 'mitre_tactic', 'best_model'
    ]].round(2)
    
    return {
        "alerts": response_df.to_dict(orient="records"),
        "metrics": metrics
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
