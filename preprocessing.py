import pandas as pd

def preprocess_alerts(df: pd.DataFrame) -> pd.DataFrame:
    """Clean and prepare alert data for ML"""
    if df.empty:
        return df
    
    df["severity"] = pd.to_numeric(df["severity"], errors="coerce").fillna(1).astype(int)
    df["frequency"] = pd.to_numeric(df["frequency"], errors="coerce").fillna(1).astype(int)
    df["risk_feature"] = df["severity"] * df["frequency"]
    
    # Ensure event_type exists
    if "event_type" not in df.columns:
        df["event_type"] = "Unknown"
    
    return df
