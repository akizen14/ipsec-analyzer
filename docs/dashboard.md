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

## Verify the release

```sh
python -m pip install ".[app,dev]" playwright
python -m pytest -q -m "not testbed"
python -m playwright install chromium
python scripts/smoke_dashboard.py
```

On Windows with Edge installed, the last command can use `--channel msedge`
instead of installing a separate Chromium browser.
