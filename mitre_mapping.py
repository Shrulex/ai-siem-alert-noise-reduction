MITRE = {
    "Login Failure": ("Credential Access", "Brute Force (T1110)"),
    "Port Scan": ("Discovery", "T1046"),
    "Malware": ("Execution", "T1204"),
    "Phishing Email": ("Initial Access", "T1566"),
    "Unknown": ("Unknown", "Unknown")
}

def map_to_mitre(event_type):
    """Map event to MITRE ATT&CK tactic/technique"""
    tactic, technique = MITRE.get(event_type, ("Unknown", "Unknown"))
    return {"tactic": tactic, "technique": technique}
