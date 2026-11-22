# Local IPsec Analyzer dashboard

The dashboard runs the same passive analyzer as the CLI and serves all assets
locally. The **Theme** control offers Light, Dark, and System and remembers the
selection in the browser.

## Start the dashboard

Create a Python 3.11+ virtual environment from the repository root.

On Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install ".[app]"
.\.venv\Scripts\ipsec-analyzer.exe web
```

On Linux or macOS:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ".[app]"
ipsec-analyzer web
```

Open <http://127.0.0.1:8000>. Pass `--port` to select a different loopback port.
Press Ctrl+C in the server terminal when you finish.

## Analyze a capture

In **Ingestion**, review the supported formats, then select a `.pcap` or
`.pcapng` file or run a bundled example. The file size gives a rough estimate
before you start. Actual timing varies with packet count, hardware, and the
number of sessions. The result shows measured processing time.

Choose a session to review **Findings** or **Evidence**. In **Export**, use PDF
or offline HTML for the executive summary or technical report. Use JSON for the
structured session record. Downloads go to the browser's configured destination.

**Saved reports** lists completed analyses, including examples, and lets you
reopen and export them after the dashboard restarts. Records are stored under
`~/.ipsec-analyzer/reports` by default. Set `IPSEC_ANALYZER_REPORT_DIR` to
use another folder. The library also reads validated session JSON from
`results/` relative to the directory where you start the dashboard.

The dashboard accepts one file up to 20 MiB, examines up to 50,000 packets, and
shows at most 64 sessions per request. It marks packet-limited results as
partial and asks for a narrower capture when the response is too large. The
upload copy exists in a temporary directory for the duration of the request.

## Security and deployment

The dashboard is a single-user loopback application. The CLI binds to
`127.0.0.1`, ignores proxy headers, and checks both the connecting address
and the request host. Keep it on loopback. A shared or public deployment
requires authentication, report ownership checks, and a separate review.

- **API.** Use `/api/v1/workspace`, `/api/v1/captures`, `/api/v1/examples/{id}`,
  and `/api/v1/reports`. The original `/api/` routes still work. API errors
  include a status and a message in `application/problem+json`.
  Use `GET /api/v1/health` for a local health check.
- **Limits.** The workers share fixed one-minute quotas of 12 analysis
  requests, 30 report requests, 12 PDF requests, and 120 other API requests.
  An exhausted quota returns HTTP 429 with `Retry-After`. Each worker can
  process two expensive requests at once. Uploads must complete within 30
  seconds. The shared counters use bound parameters in a SQLite file in
  the report directory.
- **Workers.** Pass `web --workers 2` to distribute work across two processes
  on this machine. All workers use the same local report directory and rate
  counters. Keep the report directory on a local filesystem.
- **HTTPS.** Pass `web --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem`
  to enable TLS. Use a certificate your browser trusts that matches the
  loopback hostname or address you open. Store the private key outside the
  repository and open `https://127.0.0.1:8000` if the certificate covers
  that address.

### Encrypt saved dashboard reports

Create a Fernet key file outside the repository and the report archive.
Back up the file somewhere private. You’ll need the same key to reopen
the reports. On Windows PowerShell, from the repository:

```powershell
$reportKey = Join-Path $env:USERPROFILE 'ipsec-reports.key'
.\.venv\Scripts\python.exe -c "from pathlib import Path; from cryptography.fernet import Fernet; import sys; Path(sys.argv[1]).open('xb').write(Fernet.generate_key())" $reportKey
$env:IPSEC_ANALYZER_REPORT_KEY_FILE = $reportKey
.\.venv\Scripts\ipsec-analyzer.exe web
```

On macOS or Linux:

```sh
(umask 077; ./.venv/bin/python -c 'from pathlib import Path; from cryptography.fernet import Fernet; import sys; Path(sys.argv[1]).open("xb").write(Fernet.generate_key())' "$HOME/ipsec-reports.key")
export IPSEC_ANALYZER_REPORT_KEY_FILE="$HOME/ipsec-reports.key"
./.venv/bin/ipsec-analyzer web
```

The key-creation command creates a new file exclusively. On later starts,
set the environment variable to the existing key and start the dashboard.
With the key configured, new dashboard reports are encrypted and checked
for tampering when opened. Existing JSON archives and CLI reports remain
readable in their original format. Browser downloads and the temporary
upload copy are plaintext. Use operating-system disk protection where those
files need encryption at rest.

## Verify the release

```sh
python -m pip install ".[app,dev]" playwright
python -m pytest -q -m "not testbed"
python -m playwright install chromium
python scripts/smoke_dashboard.py
```

On Windows with Edge installed, the last command can use `--channel msedge`
instead of installing a separate Chromium browser.
