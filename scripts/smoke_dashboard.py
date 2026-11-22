"""Exercise the dashboard in Chromium with the actual analyzer process."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
from contextlib import contextmanager, suppress
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.request import urlopen

from playwright.sync_api import Error, expect, sync_playwright

FIXTURE = Path(__file__).resolve().parents[1] / "tests/golden/ikev2-aes256-sha256-dh14.pcapng"


@contextmanager
def dashboard():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]

    with TemporaryDirectory(prefix="ipsec-dashboard-smoke-") as cwd, subprocess.Popen(
        [sys.executable, "-I", "-m", "analyzer.cli", "web", "--port", str(port)],
        cwd=cwd,
        env={**os.environ, "IPSEC_ANALYZER_REPORT_DIR": str(Path(cwd) / "reports")},
    ) as process:
        url = f"http://127.0.0.1:{port}"
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    with urlopen(f"{url}/api/v1/health", timeout=1) as response:
                        if response.status == 200:
                            break
                except OSError:
                    time.sleep(.15)
            else:
                raise RuntimeError("The dashboard did not start.")
            yield url
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


def check_widths(page):
    for width in (320, 768, 1024, 1440):
        page.set_viewport_size({"width": width, "height": 940})
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width


def check_examples(page):
    healthy = page.get_by_role("button", name=re.compile("Healthy tunnel"))
    healthy.focus()
    page.keyboard.press("Enter")
    expect(page.get_by_role("heading", name="Capture assessment")).to_be_focused()
    expect(page.locator("#session-metrics")).to_contain_text("100/100")
    check_widths(page)

    page.get_by_role("button", name="View Notifications").click()
    expect(page.locator(".evidence-row").filter(has_text="Notifications")).to_be_focused()
    page.get_by_role("tab", name="Evidence").focus()
    page.keyboard.press("ArrowRight")
    expect(page.get_by_role("tab", name="Export")).to_be_focused()
    for kind, name, label in (
        ("executive", "executive summary", "Executive summary"),
        ("technical", "technical report", "Technical assessment"),
    ):
        with page.expect_download() as pending:
            page.get_by_role("button", name=f"Download {name} as HTML").click()
        assert pending.value.suggested_filename.endswith(f"-{kind}.html")
        assert label in pending.value.path().read_text(encoding="utf-8")
        with page.expect_download() as pending:
            page.get_by_role("button", name=f"Download {name} as PDF").click()
        assert pending.value.suggested_filename.endswith(f"-{kind}.pdf")
        assert pending.value.path().read_bytes().startswith(b"%PDF-")
    with page.expect_download() as pending:
        page.get_by_role("button", name="Download session record as JSON").click()
    assert json.loads(pending.value.path().read_text(encoding="utf-8"))["score"]["value"] == 100

    page.get_by_role("button", name="New capture").click()
    page.get_by_role("button", name=re.compile("Weak negotiation")).click()
    expect(page.locator("#session-metrics")).to_contain_text("16/100")
    expect(page.locator("#session-metrics")).to_contain_text("High")


def check_stop_waiting(page):
    held = []
    pattern = "**/api/v1/examples/healthy"
    page.route(pattern, lambda route: held.append(route))
    page.get_by_role("button", name=re.compile("Healthy tunnel")).click()
    cancel = page.get_by_role("button", name="Stop waiting")
    expect(cancel).to_be_focused()
    expect(page.get_by_role("progressbar")).to_be_visible()
    expect(page.locator("#elapsed-time")).to_contain_text("Elapsed time")
    cancel.click()
    expect(page.get_by_role("status")).to_contain_text("Stopped waiting.")
    expect(page.get_by_role("heading", name="Capture ingestion")).to_be_visible()
    page.unroute(pattern)
    for route in held:
        # The browser may already have closed the aborted request.
        with suppress(Error):
            route.abort()


def check_uploads(page, multiple: Path | None):
    page.get_by_role("button", name="New capture").click()
    control = page.locator("#capture-file")
    control.set_input_files(FIXTURE)
    expect(page.locator("#selected-name")).to_have_text(FIXTURE.name)
    expect(page.locator("#time-estimate")).to_contain_text("Estimated processing time")
    page.get_by_role("button", name="Analyze capture").click()
    expect(page.locator("#session-metrics")).to_contain_text("100/100")
    expect(page.locator("#capture-summary")).to_contain_text("Processed in")

    if multiple:
        page.get_by_role("button", name="New capture").click()
        control.set_input_files(multiple)
        page.get_by_role("button", name="Analyze capture").click()
        sessions = page.locator("#session-list").get_by_role("button")
        expect(sessions).to_have_count(3)
        for index, cipher in enumerate(("AES_GCM_16", "AES_CTR", "AES_CBC")):
            expect(sessions.nth(index)).to_contain_text(cipher)
            sessions.nth(index).click()
            expect(page.locator("#session-suite")).to_contain_text(cipher)

    page.get_by_role("button", name="New capture").click()
    control.set_input_files({"name": "bad.txt", "mimeType": "text/plain", "buffer": b"not a capture"})
    expect(page.get_by_role("alert")).to_contain_text("Choose a .pcap or .pcapng file")
    expect(page.get_by_role("button", name="Analyze capture")).to_be_disabled()
    control.set_input_files({
        "name": "broken.pcap", "mimeType": "application/octet-stream", "buffer": b"not a capture",
    })
    page.get_by_role("button", name="Analyze capture").click()
    expect(page.get_by_role("alert")).to_contain_text("could not be read")
    expect(page.get_by_role("button", name="Analyze capture")).to_be_enabled()


def check_library(page):
    page.reload()
    page.get_by_role("button", name="Saved reports").click()
    expect(page.get_by_role("heading", name="Saved reports")).to_be_focused()
    search = page.get_by_role("searchbox", name="Search by filename")
    search.fill("not-in-the-library.pcap")
    expect(page.get_by_text("No reports match this filename.")).to_be_visible()
    search.fill("3des")
    check_widths(page)
    page.get_by_role("button", name=re.compile("Open report for .*3des")).click()
    expect(page.get_by_role("heading", name="Capture assessment")).to_be_focused()
    expect(page.locator("#session-metrics")).to_contain_text("16/100")
    page.get_by_role("tab", name="Export").click()
    expect(page.get_by_role("button", name="Download technical report as PDF")).to_be_visible()


def check_themes(page):
    theme = page.get_by_role("combobox", name="Theme")
    for name in ("dark", "light"):
        theme.select_option(name)
        assert page.evaluate("getComputedStyle(document.documentElement).colorScheme") == name
        page.reload()
        expect(theme).to_have_value(name)
        check_widths(page)
    theme.select_option("system")
    page.emulate_media(color_scheme="dark")
    expect(page.locator("html")).to_have_attribute("data-theme", "dark")
    assert page.evaluate("getComputedStyle(document.documentElement).colorScheme") == "dark"
    page.emulate_media(color_scheme="light")
    expect(page.locator("html")).to_have_attribute("data-theme", "light")
    assert page.evaluate("getComputedStyle(document.documentElement).colorScheme") == "light"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--channel", help="Browser channel, for example msedge")
    parser.add_argument("--multiple", type=Path, help="Optional Wireshark reconnect capture")
    parser.add_argument("--screenshots", type=Path, help="Optional directory for screenshots")
    args = parser.parse_args()

    with dashboard() as url, sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel=args.channel)
        page = browser.new_page(
            viewport={"width": 1440, "height": 940}, color_scheme="light", reduced_motion="no-preference",
        )
        errors: list[str] = []
        requests: list[str] = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("request", lambda request: requests.append(request.url))
        page.goto(url)
        expect(page.get_by_role("button", name=re.compile("Healthy tunnel"))).to_be_enabled()
        expect(page.get_by_role("heading", name="Supported files")).to_be_visible()
        expect(page.locator("#formats")).to_contain_text(".pcapng")
        expect(page.locator("#tunnel")).to_have_count(0)
        check_widths(page)
        check_themes(page)
        if args.screenshots:
            args.screenshots.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=args.screenshots / "ipsec-dashboard.png", full_page=True)
        check_stop_waiting(page)
        check_examples(page)
        if args.screenshots:
            page.screenshot(path=args.screenshots / "ipsec-assessment.png", full_page=True)
        check_uploads(page, args.multiple)
        check_library(page)
        assert not errors, errors
        assert all(request.startswith(f"{url}/") for request in requests), requests

        browser.close()
    print("Dashboard smoke passed: ingestion, estimates, saved reports, PDF/HTML/JSON, themes, and responsive layout.")


if __name__ == "__main__":
    main()
