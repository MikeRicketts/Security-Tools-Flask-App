"""Application configuration, driven entirely by environment variables."""
import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URI", "sqlite:///app_data.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"

    # Password for the seeded admin account. If unset, a random one is
    # generated and printed to the console once on first run.
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

    # How the port scanner is launched. Defaults to a prebuilt binary if
    # present (see Dockerfile), otherwise falls back to `go run`.
    SCANNER_BIN = os.environ.get("SCANNER_BIN")
