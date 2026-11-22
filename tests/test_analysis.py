"""Regression checks for the shared analysis entry point and its CLI caller."""

import json

import pytest
from click.testing import CliRunner

from analyzer.analysis import analyse_capture
from analyzer.cli import main


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
