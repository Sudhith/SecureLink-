"""
SecureLink AI — Entry point launcher.

Run from the SecureLink-AI directory:
    python main.py          → starts API + bot (uvicorn)
    python main.py dash     → starts Streamlit dashboard
    python main.py train    → runs model training
    python main.py test     → runs test suite
"""

import subprocess
import sys
from pathlib import Path

# Ensure we're always running with SecureLink-AI as the working directory
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "api"

    if cmd in ("api", "bot", "server"):
        print("🚀 Starting SecureLink AI API + Bot (polling mode)...")
        subprocess.run([
            sys.executable, "-m", "uvicorn",
            "app.api:app", "--reload", "--port", "8000"
        ], cwd=ROOT)

    elif cmd == "dash":
        print("📊 Starting Streamlit dashboard...")
        subprocess.run([
            sys.executable, "-m", "streamlit",
            "run", "dashboard/streamlit_app.py"
        ], cwd=ROOT)

    elif cmd == "train":
        print("🧠 Running model training...")
        subprocess.run([sys.executable, "scripts/train_model.py"], cwd=ROOT)

    elif cmd == "test":
        print("🧪 Running test suite...")
        subprocess.run([
            sys.executable, "-m", "pytest", "tests/", "-v",
            "--asyncio-mode=auto"
        ], cwd=ROOT)

    else:
        print(f"Unknown command: {cmd}")
        print("Usage: python main.py [api|dash|train|test]")
        sys.exit(1)


if __name__ == "__main__":
    main()
