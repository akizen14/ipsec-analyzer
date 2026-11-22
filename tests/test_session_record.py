"""Saved session-record round trips and validation."""

import json

import pytest

from analyzer.record import SessionRecord
from analyzer.record.validate import RecordInvalid


def test_golden_records_round_trip_through_disk(analysed, tmp_path):
    for sessions in analysed.values():
        for original in sessions:
            first = original.dump(tmp_path / f"{original.session_id}.json")
            loaded = SessionRecord.load(first)
            second = loaded.dump(tmp_path / f"{original.session_id}-loaded.json")
            assert first.read_bytes() == second.read_bytes()
            assert loaded.coverage() == original.coverage()
            assert loaded.score.value == original.score.value


@pytest.mark.parametrize(
    ("key", "replacement", "reason"),
    [
        ("schema_version", "2.0.0", "Unsupported session schema version"),
        ("child_sas", {}, "failed schema validation"),
        ("coverage", {"determinable": 0, "total": 0, "fraction": 0}, "does not match its evidence"),
    ],
)
def test_invalid_record_is_rejected(analysed, key, replacement, reason):
    record = next(iter(analysed.values()))[0]
    data = json.loads(json.dumps(record.to_json()))
    data[key] = replacement
    with pytest.raises(RecordInvalid, match=reason):
        SessionRecord.from_json(data)


def test_invalid_json_has_a_record_error(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(RecordInvalid, match="Invalid session JSON"):
        SessionRecord.load(path)
