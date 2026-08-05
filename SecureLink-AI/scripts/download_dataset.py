"""
SecureLink AI — Dataset Downloader (UCI ML Repository)

Downloads the PhiUSIIL Phishing URL Dataset directly from UCI ML Repo.
No Kaggle account needed. Requires: pip install ucimlrepo

Run from SecureLink-AI directory:
    python scripts/download_dataset.py
"""

import sys
from pathlib import Path

# ── Install ucimlrepo if missing ──────────────────────────────────────────────
try:
    from ucimlrepo import fetch_ucirepo
except ImportError:
    print("Installing ucimlrepo...")
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "ucimlrepo"], check=True)
    from ucimlrepo import fetch_ucirepo

import pandas as pd

OUTPUT_PATH = Path("data/raw/phiusiil_dataset.csv")
OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)


def main():
    print("=" * 60)
    print("Downloading PhiUSIIL dataset from UCI ML Repository...")
    print("(~235,000 URLs — may take 1-2 minutes on first run)")
    print("=" * 60)

    # Fetch dataset — id=967 is PhiUSIIL Phishing URL Dataset
    dataset = fetch_ucirepo(id=967)

    X = dataset.data.features   # Pre-extracted features (111 columns)
    y = dataset.data.targets    # Label column

    print(f"\n✅ Downloaded: {len(X)} rows, {len(X.columns)} feature columns")
    print(f"   Label distribution:\n{y.value_counts().to_string()}")

    # Combine features + label into one DataFrame
    df = pd.concat([X, y], axis=1)
    df.info()  # Show DataFrame info

    # Rename label column to what the training script expects
    # PhiUSIIL uses 'label' column with 1=phishing, 0=legitimate
    label_col = y.columns[0]
    if label_col != "label":
        df = df.rename(columns={label_col: "label"})

    # Save to CSV
    df.to_csv(OUTPUT_PATH, index=False)
    print(f"\n✅ Saved to: {OUTPUT_PATH}")
    print(f"   File size: {OUTPUT_PATH.stat().st_size / 1024 / 1024:.1f} MB")
    print("\nNow run: python scripts/train_model.py")
    print("=" * 60)


if __name__ == "__main__":
    main()
