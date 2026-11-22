"""Exercise the dashboard in Chromium with the actual analyzer process."""

from __future__ import annotations

import argparse
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
    ) as process:
        url = f"http://127.0.0.1:{port}"
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    with urlopen(f"{url}/api/workspace", timeout=1) as response:
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
    expect(page.get_by_role("tab", name="Reports")).to_be_focused()
    for kind, label in (("executive", "Executive summary"), ("technical", "Technical assessment")):
        with page.expect_download() as pending:
            page.get_by_role("button", name=f"Download {kind} report").click()
        assert pending.value.suggested_filename.endswith(f"-{kind}.html")
        assert label in pending.value.path().read_text(encoding="utf-8")

    page.get_by_role("button", name="New capture").click()
    page.get_by_role("button", name=re.compile("Weak negotiation")).click()
    expect(page.locator("#session-metrics")).to_contain_text("16/100")
    expect(page.locator("#session-metrics")).to_contain_text("High")


def check_cancel(page):
    held = []
    pattern = "**/api/examples/healthy"
    page.route(pattern, lambda route: held.append(route))
    page.get_by_role("button", name=re.compile("Healthy tunnel")).click()
    cancel = page.get_by_role("button", name="Cancel")
    expect(cancel).to_be_focused()
    expect(page.locator("#tunnel")).to_have_attribute("data-motion", "running")
    signal = page.locator("#tunnel-signal")
    expect(signal).not_to_have_text(signal.text_content())
    cancel.click()
    expect(page.get_by_role("status")).to_have_text("Analysis cancelled.")
    expect(page.get_by_role("heading", name="Inspect the tunnel.")).to_be_visible()
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
    page.get_by_role("button", name="Analyze capture").click()
    expect(page.locator("#session-metrics")).to_contain_text("100/100")

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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--channel", help="Browser channel, for example msedge")
    parser.add_argument("--multiple", type=Path, help="Optional Wireshark reconnect capture")
    parser.add_argument("--screenshots", type=Path, help="Optional directory for screenshots")
    args = parser.parse_args()

    with dashboard() as url, sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel=args.channel)
        page = browser.new_page(viewport={"width": 1440, "height": 940}, reduced_motion="no-preference")
        errors: list[str] = []
        requests: list[str] = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("request", lambda request: requests.append(request.url))
        page.goto(url)
        expect(page.get_by_role("button", name=re.compile("Healthy tunnel"))).to_be_enabled()
        check_widths(page)
        if args.screenshots:
            args.screenshots.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=args.screenshots / "ipsec-dashboard.png", full_page=True)
        check_cancel(page)
        check_examples(page)
        if args.screenshots:
            page.screenshot(path=args.screenshots / "ipsec-assessment.png", full_page=True)
        check_uploads(page, args.multiple)
        assert not errors, errors
        assert all(request.startswith(f"{url}/") for request in requests), requests

        reduced = browser.new_page(reduced_motion="reduce")
        reduced.goto(url)
        tunnel = reduced.locator("#tunnel")
        expect(tunnel).to_have_attribute("data-motion", "static")
        frame = reduced.locator("#tunnel-signal").text_content()
        expect(reduced.locator("#tunnel-signal")).to_have_text(frame)
        browser.close()
    print("Dashboard smoke passed: samples, upload, errors, evidence, reports, responsive layout, and reduced motion.")


if __name__ == "__main__":
    main()
