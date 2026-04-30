"""
GreenCode Platform - Configuration
===================================
Environment-specific configuration, isolated per NFR-05 (Portability).
"""
import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    # NFR-02: signs session cookies; override via SECRET_KEY env var in production
    SECRET_KEY = os.environ.get("SECRET_KEY") or "greencode-secret-key-change-in-production"

    # Swap to postgresql://... for production (NFR-05 Portability)
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or \
        "sqlite:///" + os.path.join(basedir, "greencode.db")

    # NFR-01: Disable tracking to save memory and CPU
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.path.join(basedir, "uploads")
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB upload limit
