"""Shared fixtures for both the English and Chinese single-file apps."""
import importlib.util
import pathlib
import tempfile

import pytest
from fastapi.testclient import TestClient


def _load_module(path, tmp_path):
    spec = importlib.util.spec_from_file_location(
        path.stem.replace(".", "_"), str(path)
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Redirect the database into a per-test temp file.
    tmpdb = tmp_path / "test.db"
    mod.DATABASE_PATH = tmpdb
    mod.initialize_database()
    return mod


@pytest.fixture(params=["magnet_share.en.py", "magnet_share.zh.py"])
def app_client(request, tmp_path):
    """Parametrized over both language variants of the single-file app."""
    root = pathlib.Path(__file__).resolve().parent.parent
    mod = _load_module(root / request.param, tmp_path)
    client = TestClient(mod.app)
    client._mod = mod
    yield client


@pytest.fixture
def registered_client(app_client):
    client = app_client
    resp = client.post(
        "/api/auth/register",
        json={"username": "alice", "password": "correct-horse"},
    )
    assert resp.status_code == 200
    token = resp.json()["token"]
    client.headers["Authorization"] = f"Bearer {token}"
    return client
