from pathlib import Path
import os

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


MODEL_PATH = Path(os.getenv(
    "SECURITY_MODEL_PATH",
    str(Path(__file__).resolve().parent / "security_model.joblib"),
))


def build_training_data():
    """Create baseline data with normal and suspicious behavior samples."""
    normal_data = [
        [0, 5, 0, 0, 0],
        [1, 8, 0, 0, 0],
        [0, 10, 0, 0, 0],
        [1, 12, 0, 0, 0],
        [0, 7, 0, 0, 0],
        [2, 15, 0, 0, 0],
        [1, 20, 0, 0, 0],
        [0, 18, 0, 0, 0],
        [2, 10, 0, 0, 0],
        [1, 14, 0, 0, 0],
    ]
    suspicious_data = [
        [8, 60, 1, 1, 1],
        [12, 100, 1, 1, 1],
        [15, 120, 1, 1, 1],
        [10, 80, 1, 0, 1],
        [20, 150, 1, 1, 1],
    ]
    return np.array(normal_data + suspicious_data, dtype=float)


def train_model():
    data = build_training_data()
    model = IsolationForest(
        contamination=0.25,
        random_state=42,
        n_estimators=200,
    )
    model.fit(data)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    return {
        "status": "success",
        "message": "Security ML model trained successfully.",
        "model_path": str(MODEL_PATH),
        "training_samples": len(data),
    }


def load_model():
    if not MODEL_PATH.exists():
        train_model()
    return joblib.load(MODEL_PATH)


def predict_security_event(features):
    values = np.asarray(features, dtype=float)
    if values.size != 5:
        raise ValueError("Expected exactly 5 security feature values.")

    model = load_model()
    values = values.reshape(1, -1)
    prediction = model.predict(values)[0]
    anomaly_score = model.decision_function(values)[0]
    return {
        "is_anomaly": bool(prediction == -1),
        "model_prediction": int(prediction),
        "anomaly_score": round(float(anomaly_score), 4),
    }