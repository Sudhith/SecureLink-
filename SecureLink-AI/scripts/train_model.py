"""
SecureLink AI — Model Training Pipeline

Usage:
    python scripts/train_model.py

This script:
  1. Looks for a CSV in data/raw/ (PhiUSIIL or compatible format)
  2. If none found, generates a synthetic 5,000-URL dataset for CI/demo
  3. Performs domain-level stratified train/test split (StratifiedGroupKFold)
  4. Trains XGBoost with probability calibration (isotonic regression)
  5. Evaluates and prints metrics
  6. Saves model.pkl, scaler.pkl, model_metadata.json

─────────────────────────────────────────────────────────────────────────────
⚠️  SYNTHETIC DATA WARNING
─────────────────────────────────────────────────────────────────────────────
If no real CSV is found, the model is trained on procedurally generated data.
This model will look like it works (high CV metrics on its own distribution)
but it has learned FAKE patterns, not real phishing behavior.

DO NOT use the shipped model for real threat detection.
DO NOT put the synthetic model's metrics on a resume.

To train on real data:
  1. Download PhiUSIIL Phishing URL Dataset from Kaggle:
     https://www.kaggle.com/datasets/drashti4/phiusiil-phishing-url-dataset
  2. Place the CSV in: SecureLink-AI/data/raw/
  3. Run: python scripts/train_model.py
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.compose import ColumnTransformer
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, OneHotEncoder, StandardScaler

# ── Project root setup ────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
DATA_RAW = ROOT / "data" / "raw"
DATA_PROCESSED = ROOT / "data" / "processed"
MODELS_DIR = ROOT / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)
DATA_PROCESSED.mkdir(parents=True, exist_ok=True)

# ── Feature columns expected by the model ────────────────────────────────────
NUMERIC_FEATURES = [
    "url_length", "num_dots", "num_slashes", "num_digits",
    "num_special_chars", "num_hyphens", "num_encoded_chars",
    "num_query_params", "directory_depth", "has_https",
    "has_ip_address", "is_shortened_url", "has_suspicious_ext",
    "suspicious_keyword_count", "url_entropy", "char_repetition",
    "subdomain_count", "domain_length", "domain_age_days",
    "ssl_is_valid", "ssl_days_remaining", "ssl_is_self_signed",
]
CATEGORICAL_FEATURES = ["tld"]
ALL_FEATURES = NUMERIC_FEATURES + CATEGORICAL_FEATURES
TARGET = "label"  # 1 = phishing, 0 = legitimate
GROUP_COL = "registered_domain"  # used for domain-level split


# ── Synthetic data generator ──────────────────────────────────────────────────

def _generate_synthetic_dataset(n: int = 5000) -> pd.DataFrame:
    """
    Generate a plausible but FAKE phishing dataset for CI/demo purposes.

    The feature distributions are loosely inspired by published phishing research
    but the labels are assigned by simple heuristic rules applied to those same
    features — this means the model will learn to recover those rules perfectly,
    not to detect real phishing. Metrics on this dataset are MEANINGLESS for
    real-world performance.
    """
    logger.warning("=" * 70)
    logger.warning("GENERATING SYNTHETIC DATASET — NOT FOR PRODUCTION USE")
    logger.warning("See the docstring in train_model.py for instructions on")
    logger.warning("using the real PhiUSIIL dataset from Kaggle.")
    logger.warning("=" * 70)

    rng = np.random.default_rng(42)
    n_phish = n // 2
    n_legit = n - n_phish

    def _make_samples(n_samples: int, is_phishing: bool) -> list[dict]:
        samples = []
        for _ in range(n_samples):
            if is_phishing:
                sample = {
                    "url_length": int(rng.integers(80, 250)),
                    "num_dots": int(rng.integers(3, 10)),
                    "num_slashes": int(rng.integers(4, 12)),
                    "num_digits": int(rng.integers(5, 20)),
                    "num_special_chars": int(rng.integers(3, 15)),
                    "num_hyphens": int(rng.integers(2, 8)),
                    "num_encoded_chars": int(rng.integers(2, 10)),
                    "num_query_params": int(rng.integers(2, 8)),
                    "directory_depth": int(rng.integers(3, 8)),
                    "has_https": int(rng.integers(0, 2)),
                    "has_ip_address": int(rng.choice([0, 1], p=[0.7, 0.3])),
                    "is_shortened_url": int(rng.choice([0, 1], p=[0.6, 0.4])),
                    "has_suspicious_ext": int(rng.choice([0, 1], p=[0.6, 0.4])),
                    "suspicious_keyword_count": int(rng.integers(1, 5)),
                    "url_entropy": round(float(rng.uniform(3.5, 5.5)), 4),
                    "char_repetition": round(float(rng.uniform(0.1, 0.35)), 4),
                    "subdomain_count": int(rng.integers(2, 6)),
                    "domain_length": int(rng.integers(15, 40)),
                    "tld": rng.choice(["tk", "ml", "ga", "cf", "gq", "xyz", "top", "info"]),
                    "domain_age_days": int(rng.choice([-1, -1, int(rng.integers(0, 60))])),
                    "ssl_is_valid": int(rng.choice([-1, 0, 1], p=[0.2, 0.4, 0.4])),
                    "ssl_days_remaining": int(rng.integers(-1, 365)),
                    "ssl_is_self_signed": int(rng.choice([-1, 0, 1], p=[0.2, 0.4, 0.4])),
                    "registered_domain": f"phish-{rng.integers(0, 2500)}.tk",
                    TARGET: 1,
                }
            else:
                sample = {
                    "url_length": int(rng.integers(20, 80)),
                    "num_dots": int(rng.integers(1, 4)),
                    "num_slashes": int(rng.integers(1, 5)),
                    "num_digits": int(rng.integers(0, 5)),
                    "num_special_chars": int(rng.integers(0, 3)),
                    "num_hyphens": int(rng.integers(0, 2)),
                    "num_encoded_chars": int(rng.integers(0, 2)),
                    "num_query_params": int(rng.integers(0, 3)),
                    "directory_depth": int(rng.integers(0, 3)),
                    "has_https": 1,
                    "has_ip_address": 0,
                    "is_shortened_url": 0,
                    "has_suspicious_ext": 0,
                    "suspicious_keyword_count": int(rng.integers(0, 2)),
                    "url_entropy": round(float(rng.uniform(2.5, 3.8)), 4),
                    "char_repetition": round(float(rng.uniform(0.05, 0.15)), 4),
                    "subdomain_count": int(rng.integers(0, 2)),
                    "domain_length": int(rng.integers(5, 20)),
                    "tld": rng.choice(["com", "org", "net", "edu", "gov", "io", "co"]),
                    "domain_age_days": int(rng.choice([-1, int(rng.integers(365, 5000))])),
                    "ssl_is_valid": int(rng.choice([1, 1, -1], p=[0.8, 0.1, 0.1])),
                    "ssl_days_remaining": int(rng.integers(30, 730)),
                    "ssl_is_self_signed": 0,
                    "registered_domain": f"legit-{rng.integers(0, 2500)}.com",
                    TARGET: 0,
                }
            samples.append(sample)
        return samples

    rows = _make_samples(n_phish, True) + _make_samples(n_legit, False)
    df = pd.DataFrame(rows)
    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df


def _load_real_dataset() -> pd.DataFrame | None:
    """
    Load a real phishing dataset CSV from data/raw/.

    Expected columns (PhiUSIIL format, or any CSV with a 'url' and 'label' column):
      - url: the raw URL string
      - label: 1 = phishing, 0 = legitimate (or 'phishing'/'legitimate')

    Returns None if no CSV is found.
    """
    csv_files = list(DATA_RAW.glob("*.csv"))
    if not csv_files:
        return None

    csv_path = csv_files[0]
    logger.info("Loading dataset: %s", csv_path)

    df = pd.read_csv(csv_path, low_memory=False)
    logger.info("Loaded %d rows, columns: %s", len(df), list(df.columns))

    # Normalize label column
    label_col = None
    for col in ["label", "Label", "status", "Status", "phishing", "class"]:
        if col in df.columns:
            label_col = col
            break

    if label_col is None:
        logger.error("No recognizable label column found. Expected: label, status, phishing, class")
        return None

    # Normalize to 0/1
    if df[label_col].dtype == object:
        df[label_col] = df[label_col].str.lower().map(
            {"phishing": 1, "legitimate": 0, "malicious": 1, "benign": 0, "good": 0, "bad": 1}
        )
    df = df.rename(columns={label_col: TARGET})
    df = df.dropna(subset=[TARGET])
    df[TARGET] = df[TARGET].astype(int)

    return df


def _engineer_features_from_url_df(df: pd.DataFrame) -> pd.DataFrame:
    """
    If the dataset only has a 'url' column (no pre-extracted features),
    extract features synchronously (no async WHOIS/SSL for training speed).
    """
    if "url_length" in df.columns:
        # Features already extracted
        return df

    if "url" not in df.columns and "URL" not in df.columns:
        logger.error("Dataset has neither pre-extracted features nor a 'url' column.")
        raise ValueError("Cannot engineer features: missing 'url' column.")

    url_col = "url" if "url" in df.columns else "URL"
    logger.info("Extracting features from %d URLs (this may take a minute)...", len(df))

    import tldextract
    from app.utils import (
        shannon_entropy, count_suspicious_keywords,
        has_ip_address, is_shortened_url,
        count_encoded_chars, has_suspicious_extension,
        char_repetition_ratio,
    )
    import urllib.parse

    records = []
    for url in df[url_col]:
        try:
            url = str(url).strip()
            parsed = urllib.parse.urlparse(url)
            ext = tldextract.extract(url)

            subdomain = ext.subdomain or ""
            subdomains = [s for s in subdomain.split(".") if s]
            tld = ext.suffix or "unknown"
            reg_domain = ext.registered_domain or ext.domain or ""

            import re as re_local

            def _special(u: str) -> int:
                return len(re_local.findall(r"[^a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]", u))

            qs = urllib.parse.parse_qs(parsed.query)
            path_segments = [s for s in parsed.path.split("/") if s]

            record = {
                "url_length": len(url),
                "num_dots": url.count("."),
                "num_slashes": url.count("/"),
                "num_digits": sum(c.isdigit() for c in url),
                "num_special_chars": _special(url),
                "num_hyphens": url.count("-"),
                "num_encoded_chars": count_encoded_chars(url),
                "num_query_params": len(qs),
                "directory_depth": len(path_segments),
                "has_https": 1 if url.lower().startswith("https://") else 0,
                "has_ip_address": 1 if has_ip_address(url) else 0,
                "is_shortened_url": 1 if is_shortened_url(url) else 0,
                "has_suspicious_ext": 1 if has_suspicious_extension(url) else 0,
                "suspicious_keyword_count": count_suspicious_keywords(url),
                "url_entropy": shannon_entropy(url),
                "char_repetition": char_repetition_ratio(url),
                "subdomain_count": len(subdomains),
                "domain_length": len(reg_domain),
                "tld": tld,
                "domain_age_days": -1,   # Not available during offline training
                "ssl_is_valid": -1,
                "ssl_days_remaining": -1,
                "ssl_is_self_signed": -1,
                "registered_domain": reg_domain,
                TARGET: df.iloc[len(records)][TARGET],
            }
            records.append(record)
        except Exception:
            continue

    return pd.DataFrame(records)


def build_preprocessor() -> ColumnTransformer:
    """
    Build the sklearn ColumnTransformer that handles numeric and categorical features.

    domain_age_days = -1 is treated as a valid sentinel value, NOT imputed.
    The model learns that -1 means "unknown" as a distinct regime.
    """
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import Pipeline as SKPipeline

    numeric_pipeline = SKPipeline([
        # No imputation — -1 values are intentional (WHOIS unavailable)
        # Only fill genuine NaN (missing rows) with median
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
    ])

    categorical_pipeline = SKPipeline([
        ("imputer", SimpleImputer(strategy="constant", fill_value="unknown")),
        ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
    ])

    return ColumnTransformer([
        ("num", numeric_pipeline, NUMERIC_FEATURES),
        ("cat", categorical_pipeline, CATEGORICAL_FEATURES),
    ])


def train_model(df: pd.DataFrame) -> tuple:
    """
    Train an XGBoost model with probability calibration.

    Uses StratifiedGroupKFold to:
      - Group by registered domain (prevents same-domain leakage)
      - Stratify by label (preserves class balance in each fold)

    This is the correct approach. Plain StratifiedKFold would allow the same
    domain to appear in both train and test, artificially inflating accuracy.
    GroupKFold without stratification would allow class imbalance per fold.
    StratifiedGroupKFold (sklearn >= 1.1) provides both guarantees simultaneously.

    Returns:
        (calibrated_pipeline, preprocessor, X_test, y_test, feature_names)
    """
    import xgboost as xgb
    from sklearn.model_selection import StratifiedGroupKFold

    X = df[ALL_FEATURES]
    y = df[TARGET].values
    groups = df[GROUP_COL].values

    logger.info(
        "Dataset: %d samples | %d phishing (%.1f%%) | %d legitimate",
        len(df),
        y.sum(),
        100 * y.mean(),
        (1 - y).sum(),
    )

    # ── Domain-level stratified split (80/20) ────────────────────────────────
    # We use StratifiedGroupKFold with n_splits=5 and take the first fold's
    # indices for the final train/test split. This gives us a ~80/20 split
    # with no domain overlap between train and test.
    sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    splits = list(sgkf.split(X, y, groups=groups))
    train_idx, test_idx = splits[0]  # Use first fold as the hold-out test set

    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    groups_train = groups[train_idx]

    logger.info(
        "Split: %d train | %d test (domain-grouped, no overlap guaranteed)",
        len(X_train),
        len(X_test),
    )

    # ── Preprocessor ─────────────────────────────────────────────────────────
    preprocessor = build_preprocessor()

    # ── XGBoost with class weight ─────────────────────────────────────────────
    # Handle class imbalance by weighting the positive class
    pos_weight = (y_train == 0).sum() / max((y_train == 1).sum(), 1)
    logger.info("Class pos_weight for XGBoost: %.2f", pos_weight)

    base_model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        scale_pos_weight=pos_weight,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )

    # ── Probability calibration ───────────────────────────────────────────────
    # Raw XGBoost probabilities are often miscalibrated. Isotonic regression
    # (better for larger datasets) corrects the probability curve so that
    # P(phishing | score=0.7) ≈ 0.7 in reality. This is what makes the
    # Trust Score meaningful rather than arbitrary.
    #
    # CalibratedClassifierCV wraps the BASE ESTIMATOR only (not a Pipeline)
    # because sklearn's calibration layer needs direct access to predict_proba.
    # We apply the preprocessor first, then calibrate the transformed data.
    calibrated = CalibratedClassifierCV(base_model, method="isotonic", cv=3)

    pipeline = Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", calibrated),
    ])

    logger.info("Training calibrated XGBoost model...")
    pipeline.fit(X_train, y_train)

    return pipeline, preprocessor, X_test, y_test


def evaluate_model(model, X_test: pd.DataFrame, y_test: np.ndarray) -> dict:
    """Evaluate the trained model and return metrics dict."""
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    roc_auc = roc_auc_score(y_test, y_prob)
    report = classification_report(y_test, y_pred, output_dict=True)
    cm = confusion_matrix(y_test, y_pred).tolist()

    logger.info("\n%s", classification_report(y_test, y_pred))
    logger.info("ROC-AUC: %.4f", roc_auc)
    logger.info("Confusion matrix:\n%s", confusion_matrix(y_test, y_pred))

    return {
        "roc_auc": round(roc_auc, 4),
        "accuracy": round(report["accuracy"], 4),
        "precision_phishing": round(report["1"]["precision"], 4),
        "recall_phishing": round(report["1"]["recall"], 4),
        "f1_phishing": round(report["1"]["f1-score"], 4),
        "confusion_matrix": cm,
    }


def save_model(model, is_synthetic: bool, metrics: dict, dataset_version: str) -> None:
    """Save the trained model and metadata."""
    model_path = MODELS_DIR / "model.pkl"
    joblib.dump(model, model_path)
    logger.info("Model saved to %s", model_path)

    metadata = {
        "version": "1.0.0",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset_version": dataset_version,
        "is_synthetic": is_synthetic,
        "model_type": "CalibratedClassifierCV(XGBoost, isotonic)",
        "features": ALL_FEATURES,
        "metrics": metrics,
        "notes": (
            "SYNTHETIC MODEL — FOR DEMO/CI ONLY. "
            "Retrain on PhiUSIIL dataset before production use."
            if is_synthetic
            else "Trained on real phishing dataset."
        ),
    }

    metadata_path = MODELS_DIR / "model_metadata.json"
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    logger.info("Metadata saved to %s", metadata_path)


def main() -> None:
    """Main training entrypoint."""
    logger.info("SecureLink AI — Model Training Pipeline")
    logger.info("=" * 60)

    # ── Load data ─────────────────────────────────────────────────────────────
    df = _load_real_dataset()
    is_synthetic = False
    dataset_version = "phiusiil_v1"

    if df is None:
        logger.warning("No CSV found in data/raw/ — using synthetic dataset.")
        df = _generate_synthetic_dataset(n=5000)
        is_synthetic = True
        dataset_version = "synthetic_v1_5000"
    else:
        # Engineer features if needed (raw URL dataset)
        df = _engineer_features_from_url_df(df)
        # Add group column if missing
        if GROUP_COL not in df.columns:
            import tldextract
            df[GROUP_COL] = df.get("url", pd.Series([""] * len(df))).apply(
                lambda u: tldextract.extract(str(u)).registered_domain or "unknown"
            )

    # Ensure group column exists
    if GROUP_COL not in df.columns:
        df[GROUP_COL] = "group_" + (df.index // 10).astype(str)

    # Drop rows with missing labels
    df = df.dropna(subset=[TARGET])
    df[TARGET] = df[TARGET].astype(int)

    logger.info("Final dataset shape: %s", df.shape)

    # ── Train ─────────────────────────────────────────────────────────────────
    model, preprocessor, X_test, y_test = train_model(df)

    # ── Evaluate ──────────────────────────────────────────────────────────────
    metrics = evaluate_model(model, X_test, y_test)

    # ── Save ──────────────────────────────────────────────────────────────────
    save_model(model, is_synthetic, metrics, dataset_version)

    if is_synthetic:
        logger.warning("=" * 70)
        logger.warning("REMINDER: This model was trained on SYNTHETIC DATA.")
        logger.warning("Metrics above are meaningless for real phishing detection.")
        logger.warning("Download PhiUSIIL from Kaggle and retrain for real use.")
        logger.warning("=" * 70)
    else:
        logger.info("=" * 60)
        logger.info("Real model trained successfully!")
        logger.info("Fill in these ATS-ready resume metrics:")
        logger.info("  Accuracy:  %.1f%%", metrics["accuracy"] * 100)
        logger.info("  ROC-AUC:   %.3f", metrics["roc_auc"])
        logger.info("  Precision: %.1f%%", metrics["precision_phishing"] * 100)
        logger.info("  Recall:    %.1f%%", metrics["recall_phishing"] * 100)
        logger.info("  F1-Score:  %.3f", metrics["f1_phishing"])
        logger.info("=" * 60)


if __name__ == "__main__":
    main()
