"""Application-layer entry point for anomaly-model training."""

from collections.abc import Iterable
from pathlib import Path
import pickle

from sklearn.ensemble import IsolationForest


def train_model(
	attempts: Iterable[int],
	model_path: str | Path | None = None,
) -> IsolationForest:
	"""Fit an anomaly detector to per-IP failed-login counts."""
	values = list(attempts)
	if not values:
		raise ValueError("At least one failed-login count is required")

	model = IsolationForest(
		contamination="auto",
		random_state=42,
		n_estimators=100,
	)
	model.fit([[value] for value in values])

	if model_path is not None:
		with Path(model_path).open("wb") as model_file:
			pickle.dump(model, model_file)

	return model

__all__ = ["train_model"]
