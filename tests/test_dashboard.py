"""The local dashboard uses the same assessment records as the CLI."""

from urllib.parse import quote

import pytest

from analyzer.record.validate import validate

TestClient = pytest.importorskip("fastapi.testclient").TestClient
HEALTHY = "ikev2-aes256-sha256-dh14.pcapng"


@pytest.fixture
def client():
    from analyzer.web.main import app

    with TestClient(app, base_url="http://127.0.0.1") as test_client:
        yield test_client


def upload(client, capture, *, name="test.pcapng"):
    return client.post(
        "/api/captures",
        headers={"Content-Type": "application/octet-stream", "X-Capture-Name": quote(name)},
        content=capture,
    )


def test_workspace_only_serves_local_hosts(client):
    assert client.get("/", headers={"host": "example.invalid"}).status_code == 400
    page = client.get("/")
    assert page.status_code == 200
    assert "Inspect the" in page.text
    assert "default-src 'self'" in page.headers["Content-Security-Policy"]
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/docs").status_code == 404


@pytest.mark.parametrize(("example", "risk", "score"), [("healthy", "low", 100), ("weak", "high", 16)])
def test_examples_return_validated_records_and_reports(client, example, risk, score):
    response = client.post(f"/api/examples/{example}")
    assert response.status_code == 200, response.text
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json()["version"] == 1
    (session,) = response.json()["sessions"]
    validate(session["record"])
    assert session["record"]["score"]["risk_level"] == risk
    assert session["record"]["score"]["value"] == score
    assert f"{score} out of 100" in session["reports"]["executive"]
    assert "Technical assessment" in session["reports"]["technical"]


def test_uploaded_file_uses_the_display_name_and_the_existing_analyzer(client, golden_dir):
    filename = "Lab & baseline.pcapng"
    response = upload(client, (golden_dir / HEALTHY).read_bytes(), name=filename)
    assert response.status_code == 200, response.text
    assessment = response.json()
    assert assessment["capture"]["name"] == filename
    (session,) = assessment["sessions"]
    validate(session["record"])
    assert session["record"]["source"]["path"] == filename
    assert session["record"]["ike"]["encr"]["value"] == "ENCR_AES_CBC"
    assert "Lab &amp; baseline.pcapng" in session["reports"]["technical"]


def test_capture_error_states(client):
    invalid = upload(client, b"invalid capture")
    assert invalid.status_code == 422
    assert "could not be read" in invalid.json()["detail"]
    empty = upload(client, b"")
    assert empty.status_code == 422
    assert "empty" in empty.json()["detail"]
    assert upload(client, b"data", name="config.txt").status_code == 415
    assert client.post("/api/examples/unknown").status_code == 404


def test_upload_limit_enforced_on_declared_and_streamed_size(client, monkeypatch):
    from analyzer.web import main

    monkeypatch.setattr(main, "MAX_BYTES", 4)
    assert upload(client, b"12345").status_code == 413
    assert upload(client, iter([b"123", b"45"])).status_code == 413


def test_partial_analysis_preserves_the_capture_warning(client, golden_dir, monkeypatch):
    from analyzer.web import main

    monkeypatch.setattr(main, "MAX_PACKETS", 2)
    response = upload(client, (golden_dir / HEALTHY).read_bytes())
    assert response.status_code == 200
    result = response.json()
    assert result["sessions"][0]["record"]["source"]["truncated"] is True
    assert "stopped after 2 packets" in result["capture"]["warnings"][0]
