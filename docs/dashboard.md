# Local IPsec Analyzer dashboard

The dashboard runs the same passive analyzer as the CLI. It serves all assets
locally and keeps the current assessment in the browser tab.

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

Open a bundled example or select a PCAP/PCAPNG you are authorized to inspect.
Once processing finishes, choose a session and review Findings or Evidence.
Reports has the executive HTML report, technical HTML report, and JSON session
record. New capture clears the current results from the workspace.

The dashboard accepts one file up to 20 MiB, examines up to 50,000 packets, and
shows at most 64 sessions per request. It marks packet-limited results as
partial and asks for a narrower capture when the response is too large. The
upload copy exists in a temporary directory for the duration of the request.
Downloads go to the browser's configured destination.

## Verify the release

```sh
python -m pip install ".[app,dev]" playwright
python -m pytest -q -m "not testbed"
python -m playwright install chromium
python scripts/smoke_dashboard.py
```

On Windows with Edge installed, the last command can use `--channel msedge`
instead of installing a separate Chromium browser.
