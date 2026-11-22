"""Serve the local dashboard and analyse one capture per request."""

from __future__ import annotations

import re
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import unquote

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import ClientDisconnect

from analyzer import __version__
from analyzer.analysis import analyse_capture
from analyzer.ingest.framing import PCAP_ENDIAN, SECTION_HEADER
from analyzer.ingest.pcap import CaptureReadError
from reports.generator.html import render

ROOT = Path(__file__).resolve().parent
MAX_BYTES = 20 * 1024 * 1024
MAX_PACKETS = 50_000
MAX_SESSIONS = 64
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

EXAMPLES = {
    "healthy": {
        "filename": "ikev2-aes256-sha256-dh14.pcapng",
        "title": "Healthy tunnel",
        "description": "AES-256 · SHA-256 · DH14",
    },
    "weak": {
        "filename": "ikev2-3des-sha1-dh2-downgrade.pcapng",
        "title": "Weak negotiation",
        "description": "3DES · SHA-1 · DH2",
    },
}

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])
app.mount("/assets", StaticFiles(directory=ROOT / "static"), name="assets")


@app.middleware("http")
async def local_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    else:
        response.headers["Cache-Control"] = "no-cache"
    return response


@app.get("/")
def workspace() -> FileResponse:
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/workspace")
def metadata() -> dict:
    return {
        "version": __version__,
        "max_capture_bytes": MAX_BYTES,
        "examples": [{"id": example_id, **example} for example_id, example in EXAMPLES.items()],
    }


def _assessment(path: Path, filename: str) -> JSONResponse:
    with path.open("rb") as capture:
        magic = capture.read(4)
    if magic not in PCAP_ENDIAN and magic != SECTION_HEADER:
        raise HTTPException(422, f"{filename} could not be read as a PCAP or PCAPNG file.")
    try:
        result = analyse_capture(path, max_packets=MAX_PACKETS)
    except CaptureReadError as error:
        raise HTTPException(422, f"{filename} could not be read as a PCAP or PCAPNG file.") from error

    if not result.packet_count:
        raise HTTPException(422, "This capture contains no packets.")
    if not result.records:
        raise HTTPException(422, "No IPsec session found. Choose a capture with IKE, ESP, or AH.")
    if len(result.records) > MAX_SESSIONS:
        raise HTTPException(413, "This capture contains too many sessions. Filter it by peer and retry.")

    sessions = []
    for record in result.records:
        record.source.path = filename
        sessions.append({
            "record": record.to_json(),
            "reports": {kind: render(record, kind=kind) for kind in ("executive", "technical")},
        })
    response = JSONResponse({
        "version": 1,
        "capture": {"name": filename, "summary": result.capture_summary, "warnings": result.warnings},
        "sessions": sessions,
    })
    if len(response.body) > MAX_RESPONSE_BYTES:
        raise HTTPException(413, "The assessment is too large to display. Filter the capture and retry.")
    return response


@app.post("/api/examples/{example_id}")
def analyse_example(example_id: str) -> JSONResponse:
    if example_id not in EXAMPLES:
        raise HTTPException(404, "This example is unavailable.")
    filename = EXAMPLES[example_id]["filename"]
    path = ROOT / "examples" / filename
    if not path.is_file():
        path = ROOT.parents[1] / "tests" / "golden" / filename
    if not path.is_file():
        raise HTTPException(503, "The bundled capture is missing. Reinstall the dashboard package.")
    return _assessment(path, filename)


@app.post("/api/captures")
async def analyse_upload(request: Request) -> JSONResponse:
    if request.headers.get("content-type") != "application/octet-stream":
        raise HTTPException(415, "Send a PCAP or PCAPNG capture.")
    encoded_name = request.headers.get("x-capture-name", "")
    filename = unquote(encoded_name).replace("\\", "/").rsplit("/", 1)[-1]
    suffix = Path(filename).suffix.lower()
    if len(filename) > 255 or not filename.isprintable() or suffix not in {".pcap", ".pcapng"}:
        raise HTTPException(415, "Choose a .pcap or .pcapng file.")

    try:
        declared = int(request.headers.get("content-length", "0"))
    except ValueError as error:
        raise HTTPException(400, "Invalid capture size.") from error
    if declared > MAX_BYTES:
        raise HTTPException(413, "The capture exceeds the 20 MiB upload limit.")
    if declared < 0:
        raise HTTPException(400, "Invalid capture size.")

    stem = re.sub(r"[^a-zA-Z0-9_.-]", "-", Path(filename).stem)[:96].strip(".-")
    if not stem or stem.split(".")[0].upper() in {
        "CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))
    }:
        stem = "capture"
    with TemporaryDirectory(prefix="ipsec-upload-") as scratch:
        path = Path(scratch) / f"{stem}{suffix}"
        received = 0
        try:
            with path.open("wb") as output:
                async for chunk in request.stream():
                    received += len(chunk)
                    if received > MAX_BYTES:
                        raise HTTPException(413, "The capture exceeds the 20 MiB upload limit.")
                    output.write(chunk)
        except ClientDisconnect as error:
            raise HTTPException(400, "The capture upload was interrupted.") from error
        if not received:
            raise HTTPException(422, "The selected capture is empty.")
        return await run_in_threadpool(_assessment, path, filename)
