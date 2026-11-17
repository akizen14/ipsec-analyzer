# Repo map for the evaluation harness

PLAN.md section 7, step E0. This lists what the `eval/` harness reads and calls, with file paths, and is checked against the code as of 2026-11-17.

## Toolchain

- Python 3.11 or newer (3.12 locally), setuptools, `pip install -e ".[dev]"` into `.venv/`.
- pytest, with the markers `testbed` and `slow`. CI runs `pytest -m "not testbed"`.
- ruff for lint, with config in `pyproject.toml`.
- Development host: Windows 11, Docker Desktop on WSL2 for the testbed. tshark and mergecap are not installed on the host. Run them in a container when E1d needs them.

## Entry points

| What | Where |
|---|---|
| CLI | `analyzer/cli.py`, installed as `ipsec-analyzer`. `analyse CAPTURE --out DIR [--no-reports]` |
| Outputs | `DIR/<session_id>.json` (the record), plus `DIR/<session_id>-technical.html` and `-executive.html` |
| In-process pipeline | `read_capture(path)` → `build_sessions(capture)` → `assess(record)` for each record → `record.to_json()` |
| Modules | `analyzer/ingest/pcap.py`, `analyzer/sessions/builder.py`, `analyzer/scoring/score.py`, `reports/generator/html.py` |

The harness should call the in-process pipeline. It is the same path the CLI takes, without the report rendering. Use the CLI where a step times or compares the whole run (E1b, E1c).

## Session record fields Table V needs

Schema: `dataset/schemas/session_record.schema.json`. Model: `analyzer/record/model.py`. There is one record per endpoint pair.

Every attribute serialises as `{"value", "evidence", "confidence", ...}`. Evidence is one of `observed`, `inferred`, `assisted` or `unknown`. Observed attributes add `packets`, inferred ones add `method`, `features`, `alternatives` and `calibrated`, and unknown ones add the reason (`analyzer/record/attribute.py`, `Attribute.to_json`).

| Table V row | Record path | Produced today? |
|---|---|---|
| IKE version | `ike.version` | Yes, Observed (IKEv2 only) |
| Offered and selected proposals | `ike.offered_proposals[]`, `ike.selected_proposal` with `encr`, `encr_key_bits`, `prf`, `integ`, `dh_group` | Yes |
| IKE suite | `ike.encr`, `ike.encr_key_bits`, `ike.prf`, `ike.integ`, `ike.dh_group` | Yes, Observed |
| Notifications, vendor IDs | `ike.notifications[]`, `ike.vendor_ids[]` | Yes |
| ESP cipher family | `child_sas[].cipher_family`. Values: `BLOCK_16B_CBC_LIKE`, `BLOCK_8B_CBC_LIKE`, `AEAD_OR_COUNTER` | Yes, Inferred or Unknown |
| ESP block size | `child_sas[].block_size_bytes` | Yes |
| ESP ICV size | `child_sas[].icv_bytes` | **No.** The field exists but is never set. |
| ESP mode | `child_sas[].mode` | **No.** Always Unknown (phase 4). |
| PFS on rekey | `child_sas[].pfs_on_rekey` and `rekeys[].key_exchange_present` | **No.** Always Unknown (phase 4). |
| Score | `score.value`, `score.risk_level`, `score.overall_confidence` | Yes |
| Coverage | `SessionRecord.coverage()`, which returns `fraction`, `determinable`, `total`, `unknowns` | Yes |
| Time-dependent fields | `generated_at` | Strip it before comparing records |

## Residue inference

`analyzer/inference/esp_structure.py`

- `infer_block_size(flow: FlowStats) -> (block_size_attr, cipher_family_attr, ResidueEvidence)`
- `FlowStats` comes from `analyzer/esp_ah/stats.py`. It can be built directly from a list of lengths: `FlowStats(spi, src, dst, packet_count=n, length_histogram=Counter(lengths))`. So E3's residue curve can call the analyzer's own function without reimplementing it.
- Lengths are ESP payload lengths, which means everything after the 8-byte SPI and sequence header. The paper's L includes those 8 bytes. That shifts every residue by 8 but leaves the count of distinct residues unchanged, and the count is what the inference uses.
- Guards: `MIN_PACKETS = 20`, `MIN_DISTINCT_LENGTHS = 4`. The paper's bound for AES-CBC against 3DES is 18 distinct lengths. See risk R12 and decision D10.

## Tests (2026-11-17)

125 tests, all passing, and ruff is clean.

| File | Covers |
|---|---|
| `tests/test_attribute.py` | Evidence-level rules on `Attribute` |
| `tests/test_messages.py` | IKE header and payload parsing |
| `tests/test_rules_and_scoring.py` | Rule predicates, score, risk and coverage |
| `tests/test_golden.py` | End-to-end on `tests/golden/*.pcapng` against `expected.json`, schema validation, re-analysis determinism |

## Not present yet

`eval/`, `app/`, `testbed/templates/`, `testbed/matrix.yaml`, an orchestrator, a manifest, mode and PFS inference, the IKEv1 parser, and `analyzer/probe/` (the package is empty).
