import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
    DATABASE_PATH = os.path.join(BASE_DIR, "instance", "logs.db")
    MODEL_TYPE = os.environ.get("MODEL_TYPE", "unsw")
    LEGACY_MODEL_PATH = os.path.join(BASE_DIR, "model", "anomaly_model.pkl")
    UNSW_MODEL_PATH = os.path.join(BASE_DIR, "model", "anomaly_model_unsw_nb15_tuned.pkl")
    UNSW_PREPROCESSOR_PATH = os.path.join(BASE_DIR, "model", "unsw_nb15_preprocessor_tuned.pkl")
    UNSW_DECISION_THRESHOLD = float(os.environ.get("UNSW_DECISION_THRESHOLD", "0.11"))
    MODEL_PATH = UNSW_MODEL_PATH if MODEL_TYPE == "unsw" else LEGACY_MODEL_PATH
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "instance", "uploads")
    ALLOWED_EXTENSIONS = {"csv", "log", "txt"}
    MAX_CONTENT_LENGTH = 20 * 1024 * 1024  # 20 MB

    # Hardcoded demo users: username -> (password, role)
    DEMO_USERS = {
        "admin": {"password": "admin123", "role": "Admin"},
        "analyst": {"password": "analyst123", "role": "Analyst"},
    }
