"""
Standalone training script for the anomaly detection model.
Run with: python model/train_model.py
Produces model/anomaly_model.pkl
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.detector import train_model
from config import Config

if __name__ == "__main__":
    csv_path = os.path.join(os.path.dirname(__file__), "..", "data", "sample_logs.csv")
    model = train_model(csv_path=csv_path, save_path=Config.MODEL_PATH)
    print(f"Model trained and saved to {Config.MODEL_PATH}")
