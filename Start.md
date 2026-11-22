# Start IPsec Analyzer

IPsec Analyzer runs locally in your browser. Give it a saved packet capture
to review IPsec sessions, security findings, and the packet evidence behind
them. Bundled captures let you try the app immediately.

## 1. Get the project

Install **Git** and **Python 3.11 or newer**. You also need a web browser.
From a terminal in the folder where you want the project, run:

```text
git clone --branch system-hardening https://github.com/akizen14/ipsec-analyzer.git
cd ipsec-analyzer
```

Run the remaining commands from this repository folder.

## 2. Install and start the dashboard

### Windows PowerShell

```powershell
py -3 --version
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install ".[app]"
.\.venv\Scripts\ipsec-analyzer.exe web
```

### macOS or Linux

```sh
python3 --version
python3 -m venv .venv
./.venv/bin/python -m pip install ".[app]"
./.venv/bin/ipsec-analyzer web
```

Check that the version printed by the first command is **3.11 or newer**.
Open [http://127.0.0.1:8000](http://127.0.0.1:8000) and leave the server
terminal open while you use the app. Press **Ctrl+C** in that terminal to
stop it. To start again later, rerun the last command from the repository.

## 3. Run your first analysis

1. In **Ingestion**, choose **Healthy tunnel** under **Example captures**.
   The bundled example should show one session with **Low** risk and a
   **100/100** security score.
2. Check **Findings** for the assessment and **Evidence** for the supporting
   packet details. The coverage figure shows how much of the configuration
   the capture let the analyzer determine.
3. Open **Export** to download an executive summary or technical report as
   **PDF** or **HTML**, or the session record as **JSON**.
4. Open **Saved reports** to find and reopen the analysis. Use **Theme**
   to switch between Light, Dark, and your system preference.

To analyze your own capture, select a `.pcap` or `.pcapng` file and check
the estimated processing time before clicking **Analyze capture**. Extract
compressed downloads first. The dashboard accepts one file up to **20 MiB**,
processes up to **50,000 packets**, and supports up to **64 sessions** per
analysis. It marks results as partial when it reaches the packet limit.

The app stores completed analysis records in `~/.ipsec-analyzer/reports`.
Browser downloads go to your usual download location.

## Optional command-line analysis

Run a bundled capture through the same analysis engine and write the
resulting JSON and HTML reports into the local `results/` directory.

Windows PowerShell:

```powershell
.\.venv\Scripts\ipsec-analyzer.exe analyse tests/golden/ikev2-aes256-sha256-dh14.pcapng --out results
```

macOS or Linux:

```sh
./.venv/bin/ipsec-analyzer analyse tests/golden/ikev2-aes256-sha256-dh14.pcapng --out results
```

## Troubleshooting

- **Port 8000 is in use.** Rerun the startup command with `web --port 8001`
  and open [http://127.0.0.1:8001](http://127.0.0.1:8001).
- **The dashboard can’t read the file.** Open the bundled example to check
  the installation. For your own file, check that it is an extracted
  PCAP or PCAPNG and that the capture includes IKE, ESP, or AH traffic.
- **Wireshark or Npcap setup is blocked.** You can still run the dashboard
  with bundled examples and analyze saved captures.

See the [dashboard runbook](docs/dashboard.md) for verification and report
storage options.
