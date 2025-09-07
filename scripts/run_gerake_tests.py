"""Run Gerake fuzz tests against a provider and export results."""

from __future__ import annotations

import argparse
import csv
import pathlib
import random
import time
from typing import Iterable

import yaml


def call_provider(provider: str, prompt: str) -> str:
    """Return a mocked response for the given provider."""
    time.sleep(0.05)
    return f"[{provider}] mock response to: {prompt}"


def iter_cases(path: pathlib.Path) -> Iterable[dict]:
    """Yield fuzz test cases from the YAML file."""
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    for case in data:
        yield case


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", required=True)
    ap.add_argument("--testcases", default="examples/gerake_suite.yaml")
    ap.add_argument("--out", default="reports/gerake_results.csv")
    args = ap.parse_args()

    cases_path = pathlib.Path(args.testcases)
    pathlib.Path(args.out).parent.mkdir(parents=True, exist_ok=True)

    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "provider",
                "test",
                "payload",
                "response",
                "latency_ms",
                "risk_score",
            ],
        )
        writer.writeheader()

        for case in iter_cases(cases_path):
            if args.provider not in case.get("providers", []):
                continue
            for payload in case.get("payloads", []):
                start = time.time()
                response = call_provider(args.provider, payload)
                latency = int((time.time() - start) * 1000)
                writer.writerow(
                    {
                        "provider": args.provider,
                        "test": case.get("name"),
                        "payload": payload,
                        "response": response,
                        "latency_ms": latency,
                        "risk_score": random.randint(0, 100),
                    }
                )

    print("Done:", args.out)


if __name__ == "__main__":
    main()
