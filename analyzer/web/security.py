"""Request boundaries for the loopback dashboard."""

from __future__ import annotations

import logging
import re
import sqlite3
from contextlib import closing
from http import HTTPStatus
from ipaddress import ip_address
from pathlib import Path
from threading import BoundedSemaphore
from time import time

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from analyzer.web import history

LOG = logging.getLogger(__name__)
WINDOW_SECONDS = 60
RATE_LIMITS = {"analysis": 12, "report": 30, "pdf": 12, "api": 120}
BUSY_WORK = BoundedSemaphore(2)
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
LOCAL_HOST = re.compile(r"(?:127\.0\.0\.1|localhost)(?::[0-9]{1,5})?", re.IGNORECASE)


def is_api(path: str) -> bool:
    return path == "/api" or path.startswith("/api/")


def problem(status: int, detail: str, headers: dict[str, str] | None = None) -> JSONResponse:
    try:
        title = HTTPStatus(status).phrase
    except ValueError:
        title = "Request failed"
    return JSONResponse(
        {"type": "about:blank", "title": title, "status": status, "detail": detail},
        status_code=status, headers=headers, media_type="application/problem+json",
    )


def take_request(database: Path, group: str, limit: int) -> int | None:
    """Count one request in a fixed window shared by workers on this host."""
    database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if database.is_symlink():
        raise OSError("Rate limit database must be a regular file")
    with closing(sqlite3.connect(database, timeout=1)) as db, db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                policy TEXT PRIMARY KEY, window INTEGER NOT NULL, used INTEGER NOT NULL
            )
        """)
        now = int(time())
        window = now // WINDOW_SECONDS
        accepted = db.execute("""
            INSERT INTO rate_limits (policy, window, used) VALUES (?, ?, 1)
            ON CONFLICT (policy) DO UPDATE SET
                used = CASE WHEN rate_limits.window = excluded.window THEN rate_limits.used + 1 ELSE 1 END,
                window = excluded.window
            WHERE rate_limits.window <> excluded.window OR rate_limits.used < ?
        """, (group, window, limit)).rowcount
    return None if accepted else WINDOW_SECONDS - now % WINDOW_SECONDS


def _rate_group(request: Request) -> str:
    path = request.url.path.removeprefix("/api/").removeprefix("v1/").rstrip("/")
    if request.method == "POST" and (path == "captures" or path.startswith("examples/")):
        return "analysis"
    if request.method == "GET" and (path == "reports" or path.startswith("reports/")):
        return "pdf" if path.endswith(".pdf") else "report"
    return "api"


def _is_loopback(host: str) -> bool:
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


async def _protected_request(request: Request, call_next) -> Response:
    if request.client is None or not _is_loopback(request.client.host):
        return problem(403, "The dashboard only accepts connections from this computer.")
    hosts = request.headers.getlist("host")
    if len(hosts) != 1 or not LOCAL_HOST.fullmatch(hosts[0]):
        return problem(400, "Use localhost or 127.0.0.1 to open the dashboard.")
    if not is_api(request.scope["path"]):
        return await call_next(request)

    origins = request.headers.getlist("origin")
    fetch_site = request.headers.get("sec-fetch-site")
    if (origins and origins != [f"{request.url.scheme}://{hosts[0]}"]) or fetch_site not in (
        None, "same-origin", "none",
    ):
        return problem(403, "Use the local workspace to access the API.")

    group = _rate_group(request)
    try:
        retry = await run_in_threadpool(
            take_request, history.directory() / ".rate-limits.sqlite3", group, RATE_LIMITS[group],
        )
    except (OSError, sqlite3.Error):
        LOG.warning("Local rate limit storage is unavailable")
        return problem(503, "The dashboard is temporarily unavailable.", {"Retry-After": "2"})
    if retry is not None:
        return problem(429, "Too many requests. Try again shortly.", {"Retry-After": str(retry)})

    if group == "api":
        return await call_next(request)
    if not BUSY_WORK.acquire(blocking=False):
        return problem(503, "The dashboard is busy. Try again shortly.", {"Retry-After": "2"})
    try:
        return await call_next(request)
    finally:
        BUSY_WORK.release()


async def protect(request: Request, call_next) -> Response:
    try:
        response = await _protected_request(request, call_next)
    except Exception as error:
        # Request content, filesystem paths, and exception messages stay out of logs and responses.
        LOG.error("Dashboard request failed (%s)", type(error).__name__)
        response = problem(500, "The dashboard could not complete the request.")
    response.headers.update(SECURITY_HEADERS)
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=86400"
    response.headers["Cache-Control"] = "no-store" if is_api(request.scope["path"]) else "no-cache"
    return response
