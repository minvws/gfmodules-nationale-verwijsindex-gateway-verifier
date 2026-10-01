import builtins
import io
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import get_config
from app.features import enabled_features
from app.routers.default import router

VERSION_JSON_CONTENT = '{"version": "v0.0.0", "git_ref": "0000000000000000000000000"}'


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _mock_open_version_json(monkeypatch: pytest.MonkeyPatch, content: str = VERSION_JSON_CONTENT) -> None:
    real_open = builtins.open

    def fake_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if str(file).endswith("version.json"):
            return io.StringIO(content)
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)


def test_version_json_returns_version_and_enabled_features(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_open_version_json(monkeypatch)

    response = client.get("/version.json")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert body["version"] == "v0.0.0"
    assert body["git_ref"] == "0000000000000000000000000"
    expected = [feature.model_dump() for feature in enabled_features(get_config())]
    assert body["features"] == expected


def test_version_json_returns_404_when_version_file_missing(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_file_not_found(*args: Any, **kwargs: Any) -> None:
        raise FileNotFoundError("missing")

    monkeypatch.setattr(builtins, "open", raise_file_not_found)

    response = client.get("/version.json")

    assert response.status_code == 404


def test_version_json_returns_404_when_version_file_invalid(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_open_version_json(monkeypatch, content="not json")

    response = client.get("/version.json")

    assert response.status_code == 404
