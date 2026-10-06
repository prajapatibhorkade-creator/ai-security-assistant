import statistics

try:
    from sklearn.ensemble import IsolationForest
except Exception:  # pragma: no cover - optional dependency may be unavailable
    IsolationForest = None


def detect_anomalies(attempts):
    """Detect unusual per-IP failed-login counts.

    Falls back to a lightweight statistical rule when scikit-learn is not
    available in the runtime environment.
    """

    if not attempts:
        return []

    numeric_attempts = [float(attempt) for attempt in attempts]

    if len(numeric_attempts) < 2:
        return [{"failed_attempts": attempts[0], "anomaly": False}]

    if IsolationForest is None:
        mean_value = statistics.mean(numeric_attempts)
        std_dev = statistics.pstdev(numeric_attempts) if len(numeric_attempts) > 1 else 0.0
        threshold = mean_value + max(2.0 * std_dev, 1.0)

        return [
            {
                "failed_attempts": attempt,
                "anomaly": float(attempt) > threshold,
            }
            for attempt in attempts
        ]

    data = [[attempt] for attempt in numeric_attempts]

    model = IsolationForest(
        contamination="auto",
        random_state=42,
        n_estimators=100,
    )

    predictions = model.fit_predict(data)

    results = []

    for attempt, prediction in zip(attempts, predictions):
        results.append({
            "failed_attempts": attempt,
            "anomaly": prediction == -1,
        })

    return results