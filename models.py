from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
import numpy as np

def cluster_alerts(X):
    """Cluster similar alerts using DBSCAN"""
    if len(X) < 2:
        return np.array([-1] * len(X))
    
    model = DBSCAN(eps=2.5, min_samples=2)
    return model.fit_predict(X)

def detect_anomalies(X):
    """Detect anomalous alerts using Isolation Forest"""
    if len(X) < 2:
        return np.array([1] * len(X))
    
    model = IsolationForest(contamination=0.1, random_state=42)
    return model.fit_predict(X)

def calculate_risk_score(severity, frequency, anomaly):
    """Calculate risk score for each alert"""
    score = severity * (frequency ** 0.5)
    if anomaly == -1:  # anomaly detected
        score *= 1.7
    return round(score, 2)
