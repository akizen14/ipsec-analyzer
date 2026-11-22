"""Offline report export from saved assessments."""

import json
import shutil

import pytest
from click.testing import CliRunner

from analyzer.cli import main


def test_both_reports_regenerate_without_the_capture(golden_dir, tmp_path):
    runner = CliRunner()
    fixture = golden_dir / "ikev2-3des-sha1-dh2-downgrade.pcapng"
    capture = tmp_path / fixture.name
    shutil.copyfile(fixture, capture)
    original = tmp_path / "original"
    result = runner.invoke(main, ["analyse", str(capture), "--out", str(original)])
    assert result.exit_code == 0, result.output
    (record,) = original.glob("*.json")
    capture.unlink()

    for kind in ("executive", "technical"):
        expected = original / f"{record.stem}-{kind}.html"
        exported = tmp_path / "exported" / expected.name
        result = runner.invoke(
            main, ["report", str(record), "--kind", kind, "--out", str(exported)]
        )
        assert result.exit_code == 0, result.output
        assert exported.read_bytes() == expected.read_bytes()


def test_report_defaults_to_a_file_next_to_the_record(analysed, tmp_path):
    session = next(iter(analysed.values()))[0]
    record = session.dump(tmp_path / "assessment.json")
    result = CliRunner().invoke(main, ["report", str(record)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "assessment-technical.html").is_file()


@pytest.mark.parametrize("case", ["invalid-json", "unassessed", "same-path"])
def test_failed_report_does_not_create_or_overwrite_output(analysed, tmp_path, case):
    session = next(iter(analysed.values()))[0]
    record = session.dump(tmp_path / "assessment.json")
    output = tmp_path / "report.html"
    if case == "invalid-json":
        record.write_text("{invalid", encoding="utf-8")
    elif case == "unassessed":
        data = json.loads(record.read_text(encoding="utf-8"))
        del data["score"]
        record.write_text(json.dumps(data), encoding="utf-8")
    else:
        output = record
    original = record.read_bytes()

    result = CliRunner().invoke(main, ["report", str(record), "--out", str(output)])
    assert result.exit_code == 1
    assert record.read_bytes() == original
    if case != "same-path":
        assert not output.exists()
