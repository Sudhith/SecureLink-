"""
SecureLink AI — SHAP Explainability Layer

Generates per-prediction SHAP values (local explanations) and combines them
with rule-based reasons for human-readable output.

Two layers of explanation:
  1. SHAP values: rigorous, model-backed, numeric contribution of each feature
  2. Rule-based reasons: plain-English signals that don't need ML to explain

Combining both is stronger than either alone:
  - SHAP gives the ML community the rigor they expect
  - Rule-based reasons make the output readable to non-technical users
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Human-readable labels for feature names
FEATURE_LABELS = {
    "url_length": "Very long URL",
    "num_dots": "Many dots in URL",
    "num_slashes": "Many slashes in URL",
    "num_digits": "Many digits in URL",
    "num_special_chars": "Many special characters",
    "num_hyphens": "Multiple hyphens",
    "num_encoded_chars": "Encoded/obfuscated characters",
    "num_query_params": "Many query parameters",
    "directory_depth": "Deep directory path",
    "has_https": "HTTPS not present",
    "has_ip_address": "IP address used instead of domain name",
    "is_shortened_url": "Shortened URL (destination hidden)",
    "has_suspicious_ext": "Suspicious file extension",
    "suspicious_keyword_count": "Phishing-related keywords in URL",
    "url_entropy": "High URL entropy (possible obfuscation)",
    "char_repetition": "Abnormal character repetition",
    "subdomain_count": "Unusual number of subdomains",
    "domain_length": "Unusually long domain name",
    "tld": "Suspicious top-level domain",
    "domain_age_days": "Very young domain (recently registered)",
    "ssl_is_valid": "Invalid or missing SSL certificate",
    "ssl_days_remaining": "SSL certificate expiring soon",
    "ssl_is_self_signed": "Self-signed SSL certificate",
}


@dataclass
class Reason:
    """A single human-readable explanation for the risk score."""

    feature: str          # Raw feature name
    label: str            # Human-readable label
    shap_value: float     # SHAP contribution (+ = more risky, - = safer)
    rule_based: bool      # True if this comes from rule logic, not SHAP
    detail: str = ""      # Optional specific detail (e.g., "9 days old")


def compute_shap_reasons(
    model,
    features_df: pd.DataFrame,
    top_n: int = 5,
) -> list[Reason]:
    """
    Compute SHAP values for a single prediction and return the top N reasons.

    Args:
        model: The trained CalibratedClassifierCV model.
        features_df: Single-row DataFrame with the URL's features.
        top_n: Number of top contributing features to return.

    Returns:
        List of Reason objects sorted by |shap_value| descending.
    """
    try:
        import shap

        # For CalibratedClassifierCV, we need to access the underlying estimator
        # SHAP's TreeExplainer works directly with XGBoost
        base_estimator = _extract_base_estimator(model)
        if base_estimator is None:
            logger.warning("Could not extract base estimator for SHAP — skipping SHAP reasons.")
            return []

        # Get the preprocessor to transform features
        preprocessor = _extract_preprocessor(model)
        if preprocessor is not None:
            transformed = preprocessor.transform(features_df)
            # Get transformed feature names for mapping back
            try:
                feature_names = preprocessor.get_feature_names_out()
            except Exception:
                feature_names = [f"f{i}" for i in range(transformed.shape[1])]
        else:
            transformed = features_df.values
            feature_names = list(features_df.columns)

        explainer = shap.TreeExplainer(base_estimator)
        shap_values = explainer.shap_values(transformed)

        # For binary classification, shap_values[1] is the phishing class
        if isinstance(shap_values, list):
            sv = shap_values[1][0]  # single row
        else:
            sv = shap_values[0]

        # Map back to original feature names where possible
        reasons = []
        for i, (name, sv_val) in enumerate(zip(feature_names, sv)):
            # Strip ColumnTransformer prefixes (num__feature_name, cat__tld_com)
            clean_name = _clean_feature_name(str(name))
            label = FEATURE_LABELS.get(clean_name, clean_name.replace("_", " ").title())
            reasons.append(Reason(
                feature=clean_name,
                label=label,
                shap_value=float(sv_val),
                rule_based=False,
            ))

        # Sort by absolute SHAP value, take top_n that increase risk (positive)
        reasons.sort(key=lambda r: r.shap_value, reverse=True)
        top_reasons = [r for r in reasons if r.shap_value > 0][:top_n]

        return top_reasons

    except Exception as exc:
        logger.warning("SHAP computation failed: %s — returning empty reasons.", exc)
        return []


def get_rule_based_reasons(features, vt_result=None, sb_result=None) -> list[Reason]:
    """
    Generate plain-English reasons based on clear rule violations.
    These are always computed (even if SHAP fails) and are more readable
    for non-technical users.

    Args:
        features: URLFeatures dataclass from feature_engineering.py
        vt_result: VTResult from vt_api.py (optional)
        sb_result: SafeBrowsingResult from safebrowsing.py (optional)
    """
    from app.feature_engineering import URLFeatures

    reasons: list[Reason] = []

    # ── URL structure signals ─────────────────────────────────────────────────
    if features.has_ip_address:
        reasons.append(Reason(
            feature="has_ip_address",
            label="Contains IP address instead of domain name",
            shap_value=0.0,
            rule_based=True,
            detail="Legitimate websites use domain names, not raw IPs.",
        ))

    if features.is_shortened_url:
        reasons.append(Reason(
            feature="is_shortened_url",
            label="Shortened URL (true destination hidden)",
            shap_value=0.0,
            rule_based=True,
        ))

    if features.has_https == 0:
        reasons.append(Reason(
            feature="has_https",
            label="No HTTPS encryption",
            shap_value=0.0,
            rule_based=True,
        ))

    if features.suspicious_keyword_count >= 2:
        reasons.append(Reason(
            feature="suspicious_keyword_count",
            label=f"Contains {features.suspicious_keyword_count} phishing-related keywords",
            shap_value=0.0,
            rule_based=True,
        ))

    if features.url_entropy > 4.0:
        reasons.append(Reason(
            feature="url_entropy",
            label=f"Unusually high URL entropy ({features.url_entropy:.2f}) — possible obfuscation",
            shap_value=0.0,
            rule_based=True,
        ))

    # ── Domain age ────────────────────────────────────────────────────────────
    if 0 <= features.domain_age_days < 30:
        reasons.append(Reason(
            feature="domain_age_days",
            label=f"Domain registered {features.domain_age_days} days ago",
            shap_value=0.0,
            rule_based=True,
            detail="Very young domains are a strong indicator of phishing.",
        ))

    # ── SSL ───────────────────────────────────────────────────────────────────
    if features.ssl_is_self_signed == 1:
        reasons.append(Reason(
            feature="ssl_is_self_signed",
            label="Self-signed SSL certificate",
            shap_value=0.0,
            rule_based=True,
        ))

    if features.ssl_is_valid == 0:
        reasons.append(Reason(
            feature="ssl_is_valid",
            label="Invalid or expired SSL certificate",
            shap_value=0.0,
            rule_based=True,
        ))

    # ── Threat intel ──────────────────────────────────────────────────────────
    if vt_result and vt_result.available and vt_result.malicious_count > 0:
        reasons.append(Reason(
            feature="vt_detections",
            label=f"{vt_result.malicious_count} security vendors flagged this URL",
            shap_value=0.0,
            rule_based=True,
            detail=f"Detected by {vt_result.malicious_count}/{vt_result.total_engines} engines.",
        ))

    if sb_result and sb_result.available and sb_result.is_flagged:
        threat_str = ", ".join(sb_result.threat_types) if sb_result.threat_types else "threats"
        reasons.append(Reason(
            feature="google_sb",
            label=f"Flagged by Google Safe Browsing ({threat_str})",
            shap_value=0.0,
            rule_based=True,
        ))

    return reasons


def merge_reasons(shap_reasons: list[Reason], rule_reasons: list[Reason], max_total: int = 5) -> list[str]:
    """
    Merge SHAP and rule-based reasons into a deduplicated list of human-readable strings.

    Rule-based reasons from threat intel (VT, Safe Browsing) are always included
    because they're the most actionable. SHAP reasons fill the remaining slots.
    """
    seen_features: set[str] = set()
    final: list[Reason] = []

    # Threat-intel rule reasons first (always show these)
    for r in rule_reasons:
        if r.feature in ("vt_detections", "google_sb") and r.feature not in seen_features:
            final.append(r)
            seen_features.add(r.feature)

    # Other rule reasons
    for r in rule_reasons:
        if r.feature not in seen_features and len(final) < max_total:
            final.append(r)
            seen_features.add(r.feature)

    # SHAP reasons fill remaining slots
    for r in shap_reasons:
        if r.feature not in seen_features and len(final) < max_total:
            final.append(r)
            seen_features.add(r.feature)

    return [f"• {r.label}" + (f" — {r.detail}" if r.detail else "") for r in final]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_base_estimator(calibrated_model):
    """Extract the underlying XGBoost estimator from a CalibratedClassifierCV."""
    try:
        # CalibratedClassifierCV wraps estimators in calibrated_classifiers_
        calibrated_classifiers = calibrated_model.calibrated_classifiers_
        if calibrated_classifiers:
            return calibrated_classifiers[0].estimator.named_steps["classifier"]
    except AttributeError:
        pass
    return None


def _extract_preprocessor(calibrated_model):
    """Extract the preprocessing pipeline from a CalibratedClassifierCV."""
    try:
        calibrated_classifiers = calibrated_model.calibrated_classifiers_
        if calibrated_classifiers:
            return calibrated_classifiers[0].estimator.named_steps["preprocessor"]
    except AttributeError:
        pass
    return None


def _clean_feature_name(name: str) -> str:
    """Strip ColumnTransformer prefixes (num__feature -> feature)."""
    if "__" in name:
        parts = name.split("__")
        return parts[-1]
    return name
