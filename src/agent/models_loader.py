"""
Singleton model loader — loads all ML models once and shares them across tools.
"""
import joblib
from pathlib import Path
import sys

# Add parent directory to path so we can import config
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import MODELS_DIR


class ModelsLoader:
    """Singleton that loads Stage 0/1/2 models once."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._loaded = False
        return cls._instance

    def load(self):
        if self._loaded:
            return

        print("[*] Loading ML models...")

        # Stage 0 — Isolation Forest (anomaly detection)
        self.stage0 = joblib.load(MODELS_DIR / "stage0.pkl", mmap_mode='r')

        # Stage 1 — Binary classifier (Benign vs Malicious)
        self.stage1_xgb = joblib.load(MODELS_DIR / "stage1_xgb.pkl", mmap_mode='r')
        self.stage1_rf = joblib.load(MODELS_DIR / "stage1_rf.pkl", mmap_mode='r')

        # Stage 2 — Multiclass classifier (attack type) - Robust tuple unpacking
        stage2_xgb_data = joblib.load(MODELS_DIR / "stage2_xgb.pkl", mmap_mode='r')
        if isinstance(stage2_xgb_data, tuple) and len(stage2_xgb_data) >= 2:
            self.stage2_xgb, self.stage2_encoder = stage2_xgb_data[0], stage2_xgb_data[1]
        else:
            self.stage2_xgb = stage2_xgb_data
            self.stage2_encoder = None
            print("[!] Warning: stage2_xgb.pkl did not contain an encoder tuple.")

        stage2_rf_data = joblib.load(MODELS_DIR / "stage2_rf.pkl", mmap_mode='r')
        if isinstance(stage2_rf_data, tuple) and len(stage2_rf_data) >= 1:
            self.stage2_rf = stage2_rf_data[0]
        else:
            self.stage2_rf = stage2_rf_data

        self._loaded = True
        print("[+] All models loaded successfully!")

    @property
    def is_loaded(self):
        return self._loaded


# Global singleton instance
models = ModelsLoader()
