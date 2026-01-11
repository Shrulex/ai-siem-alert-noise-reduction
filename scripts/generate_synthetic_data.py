import pandas as pd
import random
from datetime import datetime, timedelta

print("Generating synthetic SIEM alerts...")

alerts = []
base_time = datetime.now()

for i in range(200):
    alerts.append({
        "event_type": random.choice([
            "Login Failure", "Port Scan", "Malware", "Phishing Email"
        ]),
        "severity": random.randint(1, 5),
        "frequency": random.randint(1, 50),
        "user": random.choice(["alice", "bob", "charlie"]),
        "ip_address": f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
    })

df = pd.DataFrame(alerts)
df.to_csv("data/raw/siem_alerts.csv", index=False)
print(f"✅ Generated 200 alerts → data/raw/siem_alerts.csv")
