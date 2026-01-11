def alert_reduction_rate(total, suppressed):
    """Calculate percentage of alerts suppressed"""
    if total == 0:
        return 0.0
    return round((suppressed / total) * 100, 2)
