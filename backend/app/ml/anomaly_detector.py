"""Application-layer access to the shared anomaly detector."""

from backend.ml.anomaly_detector import detect_anomalies

__all__ = ["detect_anomalies"]
