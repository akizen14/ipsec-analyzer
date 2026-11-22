"""Regression checks for the shared analysis entry point and its CLI caller."""

import json
import struct

import pytest
from click.testing import CliRunner

from analyzer.analysis import analyse_capture
from analyzer.cli import main
from analyzer.ingest.pcap import CaptureReadError, read_capture


@pytest.mark.parametrize(
    ("name", "expected_exit"),
    [
        ("ikev2-aes256-sha256-dh14", 0),
        ("ikev2-3des-sha1-dh2-downgrade", 2),
    ],
)
def test_cli_writes_the_shared_service_result(golden_dir, tmp_path, name, expected_exit):
    capture = golden_dir / f"{name}.pcapng"
    analysis = analyse_capture(capture)
    (session,) = analysis.records
    cli = CliRunner().invoke(
        main,
        ["analyse", str(capture), "--out", str(tmp_path), "--fail-on", "high", "--no-reports"],
    )
    assert cli.exit_code == expected_exit, cli.output
    assert analysis.capture_summary in cli.output

    (output,) = tmp_path.iterdir()
    assert output.name == f"{session.session_id}.json"
    saved = json.loads(output.read_text(encoding="utf-8"))
    expected = json.loads(json.dumps(session.to_json()))
    # Separate runs may finish in different seconds.
    del saved["generated_at"]
    del expected["generated_at"]
    assert saved == expected


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "is empty"),
        (b"not a capture", "Cannot decode"),
        (struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1), "contains no packets"),
    ],
)
def test_bad_capture_is_explained_without_writing_results(tmp_path, data, message):
    capture = tmp_path / "input.pcap"
    capture.write_bytes(data)
    output = tmp_path / "output"
    result = CliRunner().invoke(main, ["analyse", str(capture), "--out", str(output)])
    assert result.exit_code == 1
    assert message in result.output
    assert not output.exists()


def test_non_ipsec_capture_has_a_distinct_outcome(tmp_path):
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
    output = tmp_path / "output"
    result = CliRunner().invoke(main, ["analyse", str(capture), "--out", str(output)])
    assert result.exit_code == 1
    assert "No IPsec session found" in result.output
    assert not output.exists()


def test_missing_capture_has_a_typed_service_error(tmp_path):
    with pytest.raises(CaptureReadError, match="Cannot read capture"):
        read_capture(tmp_path / "missing.pcap")


@pytest.mark.parametrize("format", ["pcap", "pcapng"])
def test_truncated_capture_is_not_reported_as_complete(golden_dir, tmp_path, format):
    capture = tmp_path / f"truncated.{format}"
    if format == "pcap":
        header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        packet = struct.pack("<IIII", 0, 0, 64, 64) + bytes(20)
        capture.write_bytes(header + packet)
    else:
        source = golden_dir / "ikev2-aes256-sha256-dh14.pcapng"
        capture.write_bytes(source.read_bytes()[:-1])
    output = tmp_path / "output"

    result = CliRunner().invoke(main, ["analyse", str(capture), "--out", str(output)])
    assert result.exit_code == 1
    assert "truncated" in result.output.lower()
    assert not output.exists()


def test_packet_limit_marks_saved_results_as_partial(golden_dir, tmp_path):
    capture = golden_dir / "ikev2-aes256-sha256-dh14.pcapng"
    result = CliRunner().invoke(
        main,
        ["analyse", str(capture), "--out", str(tmp_path), "--max-packets", "2"],
    )
    assert result.exit_code == 0, result.output
    assert "Partial analysis: stopped after 2 packets" in result.output
    (saved,) = tmp_path.glob("*.json")
    payload = json.loads(saved.read_text(encoding="utf-8"))
    assert payload["source"]["packet_count"] == 2
    assert payload["source"]["truncated"] is True
    assert any("Partial analysis" in warning for warning in payload["warnings"])
    reports = list(tmp_path.glob("*.html"))
    assert len(reports) == 2
    assert all("Partial capture." in p.read_text(encoding="utf-8") for p in reports)


def test_zero_packet_limit_is_rejected(golden_dir):
    capture = golden_dir / "ikev2-aes256-sha256-dh14.pcapng"
    result = CliRunner().invoke(main, ["analyse", str(capture), "--max-packets", "0"])
    assert result.exit_code == 2
    assert "Invalid value for '--max-packets'" in result.output
