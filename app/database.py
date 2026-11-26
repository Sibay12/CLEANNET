from pymongo import MongoClient
from pymongo.errors import PyMongoError

from app.config import settings

_client: MongoClient | None = None


def get_client() -> MongoClient:
    global _client
    if not settings.mongodb_uri:
        raise RuntimeError("MONGODB_URI is not configured")
    if _client is None:
        _client = MongoClient(settings.mongodb_uri, serverSelectionTimeoutMS=5000)
    return _client


def get_db():
    return get_client()[settings.mongodb_db]


def check_database() -> bool:
    try:
        get_client().admin.command("ping")
        return True
    except (PyMongoError, RuntimeError):
        return False


def initialize_indexes() -> None:
    db = get_db()
    db.devices.create_index("device_id", unique=True)
    db.devices.create_index("status")
    db.devices.create_index("created_at")


def close_database() -> None:
    global _client
    if _client is not None:
        _client.close()
        _client = None
