"""
SecureLink AI — Model Loader

Loads the trained model from disk and provides the inference interface.
Handles the "is_synthetic" flag to show a banner in the bot and dashboard.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

_model = None
_metadata: dict = {}
_model_loaded = False


def load_model(model_path: str = "./models/model.pkl") -> bool:
    """
    Load the trained model from disk.
    Returns True on success, False if model file doesn't exist.
    """
    global _model, _metadata, _model_loaded

    path = Path(model_path)
    if not path.exists():
        logger.warning(
            "Model file not found at %s. "
            "Run: python scripts/train_model.py",
            path,
        )
        return False

    try:
        _model = joblib.load(path)
        _model_loaded = True
        logger.info("Model loaded from %s", path)
    except Exception as exc:
        logger.error("Failed to load model: %s", exc)
        return False

    # Load metadata
    metadata_path = path.parent / "model_metadata.json"
    if metadata_path.exists():
        with open(metadata_path) as f:
            _metadata = json.load(f)
        is_synthetic = _metadata.get("is_synthetic", False)
        if is_synthetic:
            logger.warning(
                "⚠️  SYNTHETIC MODEL LOADED — This model was trained on procedural data, "
                "not real phishing URLs. Do not use for real threat detection."
            )
    return True


def is_synthetic_model() -> bool:
    """Return True if the loaded model was trained on synthetic data."""
    return _metadata.get("is_synthetic", True)  # default to True (safe assumption)


def get_metadata() -> dict:
    """Return the model metadata dict."""
    return _metadata.copy()


def predict(features: "URLFeatures") -> tuple[float, str]:  # type: ignore[name-defined]
    """
    Run inference on a URLFeatures object.

    Returns:
        (ml_probability, label)
        ml_probability: calibrated probability of phishing (0.0–1.0)
        label: "phishing" or "legitimate"
    """
    if not _model_loaded or _model is None:
        logger.warning("Model not loaded — returning default safe prediction.")
        return 0.1, "legitimate"

    try:
        feature_dict = features.to_dict()
        df = pd.DataFrame([feature_dict])
        # Ensure column order matches training
        from scripts.train_model import ALL_FEATURES
        df = df.reindex(columns=ALL_FEATURES, fill_value=0)

        prob = float(_model.predict_proba(df)[0][1])
        label = "phishing" if prob >= 0.5 else "legitimate"
        return prob, label

    except Exception as exc:
        logger.error("Prediction error: %s", exc)
        return 0.1, "legitimate"
