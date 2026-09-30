"""Browser acceptance for the local OFFLINE TEST harness only.

Requires Playwright Python and an existing Microsoft Edge installation. Never
point this script at the real operator desk or pass a production API token.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


def run(token: str, *, screenshot: Path | None = None) -> Path:
    screenshot = screenshot or Path(".sentinelops/operator-offline-browser.png").resolve()
    screenshot.parent.mkdir(parents=True, exist_ok=True)
    incident_id = "inc-offline-browser-smoke"
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="msedge", headless=True)
        try:
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            page.set_default_timeout(15000)
            errors: list[str] = []
            page.on("pageerror", lambda error: errors.append(type(error).__name__))
            page.goto("http://127.0.0.1:8768/", wait_until="networkidle")
            expect(page.locator("html")).to_have_attribute("data-offline-script-loaded", "yes")
            expect(page.get_by_text("OFFLINE TEST · 假来源")).to_be_visible()

            page.locator("#token").fill(token)
            page.locator("#connect").click()
            expect(page.locator("#notice")).to_contain_text("连接成功")
            expect(page.locator("#status")).to_contain_text("就绪")
            print("PASS browser connection")

            page.locator("#incident-id").fill(incident_id)
            page.locator("#tenant-id").fill("offline-test")
            page.locator("#service").fill("demo-service")
            started = (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M")
            page.locator("#started-at").fill(started)
            page.locator("#symptoms").fill("Synthetic 5xx increase")
            page.locator("#check").click()
            expect(page.locator("#notice")).to_contain_text("所有配置来源均可读取")
            expect(page.locator("#checks .check.ok")).to_have_count(2)
            page.locator("#confirm").check()
            expect(page.locator("#run")).to_be_enabled()
            print("PASS browser source check and explicit confirmation")

            page.locator("#run").click()
            expect(page.locator("#notice")).to_contain_text("调查完成")
            expect(page.locator("#result")).to_be_visible()
            expect(page.locator("#result-meta")).to_contain_text("审计 完整")
            page.screenshot(path=str(screenshot), full_page=True)
            print("PASS browser investigation, audit, and result")

            page.reload(wait_until="networkidle")
            page.locator("#token").fill(token)
            page.locator("#connect").click()
            expect(page.locator("#notice")).to_contain_text("连接成功")
            page.locator("#incident-id").fill(incident_id)
            page.locator("#recover").click()
            expect(page.locator("#notice")).to_contain_text("已找回结果")
            expect(page.locator("#result")).to_be_visible()
            print("PASS browser reload and saved-result recovery")

            page.locator("#incident-id").fill("inc-offline-never-started")
            page.locator("#recover").click()
            expect(page.locator("#notice")).to_contain_text("当前数据库没有该事故的运行预留")
            print("PASS browser missing-run state")
            assert not errors, f"browser page errors: {errors}"
            print(f"Screenshot: {screenshot}")
            return screenshot
        finally:
            browser.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Check the offline operator page in Edge")
    parser.add_argument("--token", required=True, help="temporary token printed by the offline harness")
    args = parser.parse_args()
    run(args.token)


if __name__ == "__main__":
    main()
