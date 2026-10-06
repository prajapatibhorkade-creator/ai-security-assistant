from typing import List


def calculate_historical_risk(previous_scores: List[float]) -> float:
    """Weight prior average and most recent risk as historical context."""
    if not previous_scores:
        return 0.0

    valid_scores = [max(0, min(float(score), 100)) for score in previous_scores]
    average_score = sum(valid_scores) / len(valid_scores)
    recent_score = valid_scores[-1]
    historical_score = average_score * 0.4 + recent_score * 0.6
    return round(min(100, historical_score), 2)