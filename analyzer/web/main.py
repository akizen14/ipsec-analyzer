"""Serve the local dashboard and analyse one capture per request."""

from __future__ import annotations

import re
from asyncio import timeout
from contextlib import asynccontextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter
from typing import Literal
from urllib.parse import quote, unquote

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import ClientDisconnect

from analyzer import __version__
from analyzer.analysis import analyse_capture
from analyzer.ingest.framing import PCAP_ENDIAN, SECTION_HEADER
from analyzer.ingest.pcap import CaptureReadError
from analyzer.record import SessionRecord
from analyzer.web import history, security
from reports.generator.html import render

ROOT = Path(__file__).resolve().parent
MAX_BYTES = 20 * 1024 * 1024
MAX_PACKETS = 50_000
MAX_SESSIONS = 64
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
UPLOAD_TIMEOUT_SECONDS = 30
CAPTURE_FORMATS = {
    ".pcap": ("PCAP", "Classic packet capture from tools such as tcpdump and Wireshark."),
    ".pcapng": ("PCAPNG", "Packet capture with interface metadata, commonly saved by Wireshark."),
}

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

@asynccontextmanager
async def lifespan(_app: FastAPI):
    history.report_cipher()
    yield


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.middleware("http")(security.protect)
app.mount("/assets", StaticFiles(directory=ROOT / "static"), name="assets")
api = APIRouter()


@app.exception_handler(StarletteHTTPException)
async def request_error(request: Request, error: StarletteHTTPException) -> Response:
    if security.is_api(request.url.path):
        detail = error.detail if isinstance(error.detail, str) else "The request could not be completed."
        return security.problem(error.status_code, detail, error.headers)
    return await http_exception_handler(request, error)


@app.exception_handler(RequestValidationError)
async def invalid_request(_request: Request, _error: RequestValidationError) -> Response:
    return security.problem(422, "The request parameters are invalid.")


@app.get("/")
def workspace() -> FileResponse:
    return FileResponse(ROOT / "static" / "index.html")


@api.get("/health")
def health() -> dict:
    return {"status": "ok"}


@api.get("/workspace")
def metadata() -> dict:
    return {
        "version": __version__,
        "max_capture_bytes": MAX_BYTES,
        "max_packets": MAX_PACKETS,
        "max_sessions": MAX_SESSIONS,
        "capture_formats": [
            {"extension": extension, "name": name, "description": description}
            for extension, (name, description) in CAPTURE_FORMATS.items()
        ],
        "examples": [{"id": example_id, **example} for example_id, example in EXAMPLES.items()],
    }


def _sessions(records: list[SessionRecord] | tuple[SessionRecord, ...]) -> list[dict]:
    return [
        {"record": record.to_json(), "reports": {
            kind: render(record, kind=kind) for kind in ("executive", "technical")
        }}
        for record in records
    ]


def _assessment(path: Path, filename: str, *, example: bool = False) -> JSONResponse:
    started = perf_counter()
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

    for record in result.records:
        record.source.path = filename
    sessions = _sessions(result.records)
    capture = {"name": filename, "summary": result.capture_summary, "warnings": result.warnings}
    payload = {"version": 1, "capture": capture, "sessions": sessions}
    if len(JSONResponse(payload).body) > MAX_RESPONSE_BYTES:
        raise HTTPException(413, "The assessment is too large to display. Filter the capture and retry.")
    seconds = round(perf_counter() - started, 3)
    try:
        saved = history.save(capture, [session["record"] for session in sessions], example=example, seconds=seconds)
    except (OSError, ValueError) as error:
        raise HTTPException(507, "The report could not be saved. Check the report folder and try again.") from error
    return JSONResponse({**payload, "id": saved["id"], "processing_seconds": seconds})


@api.get("/reports")
def saved_reports() -> dict:
    entries, unreadable = history.list_entries()
    return {"reports": entries, "unreadable": unreadable}


def _saved_report(report_id: str) -> dict:
    if not re.fullmatch(r"(?:cli-)?[0-9a-f]{32}", report_id):
        raise HTTPException(404, "This report was not found.")
    try:
        return history.load(report_id)
    except FileNotFoundError as error:
        raise HTTPException(404, "This report was not found.") from error
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise HTTPException(422, "This saved report could not be read.") from error


@api.get("/reports/{report_id}")
def open_report(report_id: str) -> dict:
    entry = _saved_report(report_id)
    try:
        records = [SessionRecord.from_json(record) for record in entry["records"]]
    except (ValueError, KeyError, TypeError) as error:
        raise HTTPException(422, "This saved report could not be read.") from error
    response = JSONResponse({
        "version": 1,
        "id": report_id,
        "capture": entry["capture"],
        "processing_seconds": entry["processing_seconds"],
        "sessions": _sessions(records),
    })
    if len(response.body) > MAX_RESPONSE_BYTES:
        raise HTTPException(413, "The saved assessment is too large to display.")
    return response


@api.get("/reports/{report_id}/{session_index}/{kind}.pdf")
def download_pdf(report_id: str, session_index: int, kind: Literal["executive", "technical"]) -> Response:
    from reports.generator.pdf import render_pdf

    entry = _saved_report(report_id)
    if not 0 <= session_index < len(entry["records"]):
        raise HTTPException(404, "This session was not found.")
    try:
        record = SessionRecord.from_json(entry["records"][session_index])
    except (ValueError, KeyError, TypeError) as error:
        raise HTTPException(422, "This saved report could not be read.") from error
    try:
        pdf = render_pdf(record, kind=kind)
    except RuntimeError as error:
        raise HTTPException(500, "PDF generation failed. You can still download the HTML report.") from error
    filename = quote(f"{record.session_id}-{kind}.pdf", safe="")
    return Response(pdf, media_type="application/pdf", headers={
        "Content-Disposition": f"attachment; filename*=UTF-8''{filename}",
    })


@api.post("/examples/{example_id}")
def analyse_example(example_id: str) -> JSONResponse:
    if example_id not in EXAMPLES:
        raise HTTPException(404, "This example is unavailable.")
    filename = EXAMPLES[example_id]["filename"]
    path = ROOT / "examples" / filename
    if not path.is_file():
        path = ROOT.parents[1] / "tests" / "golden" / filename
    if not path.is_file():
        raise HTTPException(503, "The bundled capture is missing. Reinstall the dashboard package.")
    return _assessment(path, filename, example=True)


@api.post("/captures")
async def analyse_upload(request: Request) -> JSONResponse:
    if request.headers.get("content-type") != "application/octet-stream":
        raise HTTPException(415, "Send a PCAP or PCAPNG capture.")
    encoded_name = request.headers.get("x-capture-name", "")
    try:
        filename = unquote(encoded_name, errors="strict").replace("\\", "/").rsplit("/", 1)[-1]
    except UnicodeDecodeError as error:
        raise HTTPException(415, "Choose a .pcap or .pcapng file.") from error
    suffix = Path(filename).suffix.lower()
    if len(filename) > 255 or not filename.isprintable() or suffix not in CAPTURE_FORMATS:
        raise HTTPException(415, "Choose a .pcap or .pcapng file.")

    sizes = request.headers.getlist("content-length")
    declared = None
    if sizes:
        if len(sizes) != 1 or not re.fullmatch(r"[0-9]{1,20}", sizes[0]):
            raise HTTPException(400, "Invalid capture size.")
        declared = int(sizes[0])
        if declared > MAX_BYTES:
            raise HTTPException(413, "The capture exceeds the 20 MiB upload limit.")

    stem = re.sub(r"[^a-zA-Z0-9_.-]", "-", Path(filename).stem)[:96].strip(".-")
    if not stem or stem.split(".")[0].upper() in {
        "CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))
    }:
        stem = "capture"
    with TemporaryDirectory(prefix="ipsec-upload-") as scratch:
        path = Path(scratch) / f"{stem}{suffix}"
        received = 0
        try:
            async with timeout(UPLOAD_TIMEOUT_SECONDS):
                with path.open("wb") as output:
                    async for chunk in request.stream():
                        received += len(chunk)
                        if received > MAX_BYTES:
                            raise HTTPException(413, "The capture exceeds the 20 MiB upload limit.")
                        output.write(chunk)
        except ClientDisconnect as error:
            raise HTTPException(400, "The capture upload was interrupted.") from error
        except TimeoutError as error:
            raise HTTPException(408, "The capture upload took too long. Please retry.") from error
        if declared is not None and received != declared:
            raise HTTPException(400, "The capture size did not match the request.")
        if not received:
            raise HTTPException(422, "The selected capture is empty.")
        return await run_in_threadpool(_assessment, path, filename)


app.include_router(api, prefix="/api/v1")
# Keep the routes published by the original dashboard available.
app.include_router(api, prefix="/api", include_in_schema=False)
