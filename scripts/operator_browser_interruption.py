"""Close the browser during an OFFLINE TEST run and verify read-only recovery."""

from __future__ import annotations

import argparse
import time
from datetime import datetime, timedelta
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


def connect(page, token: str) -> None:
    page.goto("http://127.0.0.1:8768/", wait_until="networkidle")
    expect(page.get_by_text("OFFLINE TEST · 假来源")).to_be_visible()
    page.locator("#token").fill(token)
    page.locator("#connect").click()
    expect(page.locator("#notice")).to_contain_text("连接成功")


def run(token: str, *, screenshot: Path | None = None) -> Path:
    incident_id = "inc-offline-interrupted-browser"
    screenshot = screenshot or Path(".sentinelops/operator-offline-interruption.png").resolve()
    screenshot.parent.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="msedge", headless=True)
        try:
            page = browser.new_page()
            connect(page, token)
            page.locator("#incident-id").fill(incident_id)
            page.locator("#tenant-id").fill("offline-test")
            page.locator("#service").fill("demo-service")
            started = (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M")
            page.locator("#started-at").fill(started)
            page.locator("#symptoms").fill("Synthetic slow request")
            page.locator("#check").click()
            expect(page.locator("#notice")).to_contain_text("所有配置来源均可读取")
            page.locator("#confirm").check()
            with page.expect_request("**/api/investigate"):
                page.locator("#run").click()
            page.close()
            print("PASS browser closed after investigation request started")

            reopened = browser.new_page()
            connect(reopened, token)
            reopened.locator("#incident-id").fill(incident_id)
            reopened.locator("#recover").click()
            expect(reopened.locator("#notice")).to_contain_text("有运行预留，但尚无已保存结果")
            print("PASS in-flight reservation visible after browser disconnect")

            deadline = time.monotonic() + 20
            while True:
                with reopened.expect_response(lambda response: response.url.endswith("/api/recover")) as pending:
                    reopened.locator("#recover").click()
                print(f"OFFLINE recovery probe HTTP {pending.value.status}", flush=True)
                if pending.value.status == 200:
                    break
                if time.monotonic() >= deadline:
                    raise AssertionError("offline investigation did not finish within 20 seconds")
                reopened.wait_for_timeout(2000)
            expect(reopened.locator("#notice")).to_contain_text("已找回结果")
            expect(reopened.locator("#result-meta")).to_contain_text("查询 2 次")
            expect(reopened.locator("#result-meta")).to_contain_text("审计 完整")
            reopened.screenshot(path=str(screenshot), full_page=True)
            print("PASS completed result recovered without browser resubmission")
            print(f"Screenshot: {screenshot}")
            return screenshot
        finally:
            browser.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Check offline browser interruption recovery")
    parser.add_argument("--token", required=True, help="temporary offline-harness token only")
    args = parser.parse_args()
    run(args.token)


if __name__ == "__main__":
    main()
