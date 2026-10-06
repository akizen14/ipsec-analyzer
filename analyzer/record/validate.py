"""Validate a session record against the JSON Schema.

The schema is the published contract; the dataclasses in ``model.py`` are one
implementation of it. Keeping a real validator in the loop is what stops the two
from drifting apart, and it is the check CI runs over every golden fixture.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path
from typing import Any

import jsonschema

#: Repository root, found by walking up from this file.
_ROOT = Path(__file__).resolve().parents[2]

SCHEMA_PATH = _ROOT / "dataset" / "schemas" / "session_record.schema.json"


class RecordInvalid(ValueError):
    """Raised when a record does not satisfy the session record schema."""


@functools.lru_cache(maxsize=1)
def load_schema() -> dict[str, Any]:
    """Read and cache the session record schema."""
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@functools.lru_cache(maxsize=1)
def _validator() -> jsonschema.protocols.Validator:
    schema = load_schema()
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema)


def validate(record: dict[str, Any] | Any) -> None:
    """Raise :class:`RecordInvalid` if the record does not match the schema.

    Accepts either a plain dict or anything exposing ``to_json``, so a
    ``SessionRecord`` can be checked without the caller serialising it first.
    """
    payload = record.to_json() if hasattr(record, "to_json") else record
    errors = sorted(_validator().iter_errors(payload), key=lambda e: list(e.absolute_path))
    if not errors:
        return

    lines = []
    for err in errors:
        where = "/" + "/".join(str(p) for p in err.absolute_path) if err.absolute_path else "(root)"
        lines.append(f"  {where}: {err.message}")
    raise RecordInvalid(
        f"session record failed schema validation ({len(errors)} problem(s)):\n"
        + "\n".join(lines)
    )


def is_valid(record: dict[str, Any] | Any) -> bool:
    """Boolean form of :func:`validate`, for call sites that only want a check."""
    try:
        validate(record)
    except RecordInvalid:
        return False
    return True
