"""The local dashboard uses the same assessment records as the CLI."""

import json
from io import BytesIO
from urllib.parse import quote

import pytest

from analyzer.record.validate import validate

TestClient = pytest.importorskip("fastapi.testclient").TestClient
HEALTHY = "ikev2-aes256-sha256-dh14.pcapng"


@pytest.fixture
def client(monkeypatch, tmp_path):
    from analyzer.web.main import app

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("IPSEC_ANALYZER_REPORT_DIR", str(tmp_path / "archive"))
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
    assert "Capture ingestion" in page.text
    assert "Saved reports" in page.text
    assert client.get("/assets/motion.js").status_code == 404
    assert "default-src 'self'" in page.headers["Content-Security-Policy"]
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/docs").status_code == 404
    formats = client.get("/api/workspace").json()["capture_formats"]
    assert [item["extension"] for item in formats] == [".pcap", ".pcapng"]
    assert client.post("/api/examples/healthy", headers={"Origin": "http://example.invalid"}).status_code == 403


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


def test_non_ipsec_capture_has_a_distinct_message(client, tmp_path):
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    capture = tmp_path / "ordinary.pcap"
    packet = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.1", dst="192.0.2.2")
        / UDP(dport=53)
    )
    wrpcap(str(capture), packet)
    response = upload(client, capture.read_bytes(), name="ordinary.pcap")
    assert response.status_code == 422
    assert response.json()["detail"].startswith("No IPsec session found")


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


def test_report_library_reopens_the_saved_session_with_exports(client, tmp_path):
    from pypdf import PdfReader

    assert client.get("/api/reports").json() == {"reports": [], "unreadable": 0}
    created = client.post("/api/examples/weak").json()
    report_id = created["id"]
    assert (tmp_path / "archive" / f"{report_id}.json").is_file()
    assert created["processing_seconds"] >= 0

    (row,) = client.get("/api/reports").json()["reports"]
    assert row["id"] == report_id
    assert row["source"] == "example"
    assert row["session_count"] == 1
    assert row["worst_risk"] == "high"
    reopened = client.get(f"/api/reports/{report_id}").json()
    assert reopened == created

    for kind, expected in (("executive", "16 out of 100"), ("technical", "IKE security association")):
        export = client.get(f"/api/reports/{report_id}/0/{kind}.pdf")
        assert export.status_code == 200, export.text
        assert export.headers["Content-Type"] == "application/pdf"
        assert export.headers["Content-Disposition"].endswith(f"-{kind}.pdf")
        assert export.content.startswith(b"%PDF-")
        assert expected in " ".join(
            text for page in PdfReader(BytesIO(export.content)).pages for text in page.extract_text().split()
        )
    assert client.get(f"/api/reports/{report_id}/1/technical.pdf").status_code == 404
    assert client.get("/api/reports/invalid").status_code == 404


def test_library_shows_existing_cli_records_and_ignores_broken_files(client, tmp_path):
    record = client.post("/api/examples/healthy").json()["sessions"][0]["record"]
    directory = tmp_path / "results"
    directory.mkdir()
    (directory / "existing.json").write_text(json.dumps(record), encoding="utf-8")
    (directory / "broken.json").write_text("{", encoding="utf-8")
    library = client.get("/api/reports").json()
    assert library["unreadable"] == 1
    (cli,) = [row for row in library["reports"] if row["source"] == "cli"]
    reopened = client.get(f"/api/reports/{cli['id']}").json()
    assert reopened["sessions"][0]["record"] == record
    assert reopened["processing_seconds"] is None
