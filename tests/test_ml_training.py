import math

import pytest
from fastapi.testclient import TestClient

from backend.app.analytics import generate_security_analytics
from backend.app.main import app
from backend.app.ml import training
from backend.app.ml.evaluation import evaluate_predictions
from backend.app.security_simulator import simulate_brute_force, simulate_privilege_escalation


client = TestClient(app)


def test_model_train_save_load_predict_round_trip(tmp_path, monkeypatch):
    model_path = tmp_path / "security_model.joblib"
    monkeypatch.setattr(training, "MODEL_PATH", model_path)

    result = training.train_model()
    prediction = training.predict_security_event([12, 100, 1, 1, 1])

    assert result["status"] == "success"
    assert result["training_samples"] == 15
    assert model_path.is_file()
    assert isinstance(prediction["is_anomaly"], bool)
    assert prediction["model_prediction"] in {-1, 1}
    assert math.isfinite(prediction["anomaly_score"])


def test_predict_rejects_wrong_feature_count():
    with pytest.raises(ValueError, match="exactly 5"):
        training.predict_security_event([1, 2, 3])


def test_evaluation_metrics_and_endpoint():
    metrics = evaluate_predictions([0, 0, 1, 1], [0, 0, 1, 1])
    assert metrics == {
        "accuracy": 1.0,
        "precision": 1.0,
        "recall": 1.0,
        "f1_score": 1.0,
        "confusion_matrix": [[2, 0], [0, 2]],
    }

    response = client.get("/security/ml/evaluation")
    assert response.status_code == 200
    assert response.json()["metrics"]["accuracy"] == 1.0


def test_analytics_and_simulators():
    analytics = generate_security_analytics([
        {"event_type": "failed_login", "severity": "high", "risk_level": "HIGH", "risk_score": 70},
        {"event_type": "failed_login", "severity": "medium", "risk_level": "LOW", "risk_score": 10},
    ])
    assert analytics["total_events"] == 2
    assert analytics["event_types"] == {"failed_login": 2}
    assert analytics["average_risk_score"] == 40.0
    assert generate_security_analytics([])["total_events"] == 0

    brute_force = simulate_brute_force(attempts=4)
    privilege_chain = simulate_privilege_escalation()
    assert len(brute_force) == 5
    assert brute_force[-1]["event_type"] == "successful_login"
    assert [event["event_type"] for event in privilege_chain] == [
        "successful_login",
        "privilege_change",
        "sensitive_access",
    ]