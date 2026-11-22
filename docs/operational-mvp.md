# IPsec Analyzer operator runbook

The operational MVP assesses local PCAP and PCAPNG captures. It writes validated
session records and, by default, an executive and technical HTML report for each.
Fresh IKEv2 negotiations between the same peers receive separate reports.
Use captures you are authorized to analyze.

## Run the demo

Install from the checkout with Python 3.11 or newer. For a clean verification,
create a virtual environment, activate it, and run `python -m pip install .`.
On Windows you can run `.venv\Scripts\ipsec-analyzer.exe` directly if the
environment is inactive.

```sh
ipsec-analyzer analyse tests/golden/ikev2-aes256-sha256-dh14.pcapng --out demo-results/healthy
ipsec-analyzer analyse tests/golden/ikev2-3des-sha1-dh2-downgrade.pcapng --out demo-results/weak --fail-on high
ipsec-analyzer report demo-results/weak/ikev2-3des-sha1-dh2-downgrade-01.json --kind executive
ipsec-analyzer report demo-results/weak/ikev2-3des-sha1-dh2-downgrade-01.json --kind technical
```

The healthy fixture should score at least 95 with Low risk. The weak fixture
should score at most 40 with High risk. With the flag shown above, the weak
run exits with status 2 after publishing its outputs. Open the HTML reports
in a browser. The `report` commands can run with the source capture absent.
Use `--out path/to/report.html` to export separately from the original files.

## Interpret the result

Read score, risk, and coverage together. The score aggregates deductions.
Risk reflects the most severe actionable finding. Coverage is the number of
attributes the analyzer could determine out of the attributes it assessed.
An Unknown attribute describes a gap in evidence and does not cost points.
Read the supporting packets or inference method before acting on a finding.

- Exit status **0** means analysis succeeded. Without `--fail-on`, even a
  High-risk result can exit 0.
- Exit status **1** indicates a runtime error, such as invalid input, a
  capture with no IPsec session, an invalid saved record, or an output error.
- Exit status **2** with the threshold message means the requested risk
  threshold was reached. CLI argument errors also use status 2 and show usage.

Use `--max-packets N` to bound the analysis to the first (N) packets. When the
file contains more packets, the CLI and both reports mark the assessment partial.
Use a separate output directory for each run so its files are easy to identify.
The analyzer stages all files before publishing them. When reusing an existing
directory, it replaces individual files after staging.

The two committed captures are about 38 KiB and 147 KiB. A clean Windows wheel
smoke test processed each in about one second, including CLI startup. The sample
timings do not establish a performance limit for larger captures. Scapy can
print an Npcap service warning on Windows even when offline processing succeeds.

## Verify an installed build

Run `python scripts/smoke_installed.py` from a checkout. The script builds a
wheel, installs it into a temporary environment, and runs the actual CLI from
outside the checkout. It checks the two fixture verdicts, verifies identical
reports after removing the temporary capture copies, and confirms corrupt input
creates no output directory. CI runs this check on Windows and Ubuntu.
