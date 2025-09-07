"""Send a summary of results to Slack via an incoming webhook."""

from __future__ import annotations

import argparse
import os
import pathlib

import requests


def send_slack(webhook: str, text: str) -> None:
    response = requests.post(webhook, json={"text": text})
    response.raise_for_status()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True, help="CSV file to send")
    ap.add_argument("--webhook", help="Slack webhook URL")
    args = ap.parse_args()

    webhook = args.webhook or os.getenv("SLACK_WEBHOOK_URL")
    if not webhook:
        print("Missing Slack webhook URL. Set SLACK_WEBHOOK_URL or use --webhook.")
        return

    path = pathlib.Path(args.file)
    if not path.exists():
        print("File not found:", path)
        return

    snippet = path.read_text(encoding="utf-8")[:1000]
    try:
        send_slack(webhook, f"Results from {path}\n```{snippet}```")
        print("Sent to Slack")
    except requests.RequestException as exc:
        print("Slack request failed:", exc)


if __name__ == "__main__":
    main()
