"""Run OWASP LLM Top 10 tests and save results.

This script loads a YAML file describing prompts for each OWASP risk
category, calls a mocked provider for each prompt, and writes the output to a
CSV file. The mock implementation can later be replaced with real API calls
and risk-scoring engines.
"""

from __future__ import annotations

import argparse
import csv
import pathlib
import random
import time
from typing import Iterable

import yaml


def mock_call(prompt: str) -> str:
    """Return a mocked provider response for the given prompt."""

    time.sleep(0.02)
    return f"mock: {prompt}"


def iter_tests(path: pathlib.Path) -> Iterable[dict]:
    """Yield test cases from the provided YAML file."""

    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    for test in data:
        yield test


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tests", default="models/owasp_llm_top10_tests.yaml")
    parser.add_argument("--out", default="reports/owasp_results.csv")
    args = parser.parse_args()

    tests_path = pathlib.Path(args.tests)
    pathlib.Path(args.out).parent.mkdir(parents=True, exist_ok=True)

    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["owasp_id", "name", "prompt", "response", "risk_score"],
        )
        writer.writeheader()

        for t in iter_tests(tests_path):
            for prompt in t.get("prompts", []):
                response = mock_call(prompt)
                writer.writerow(
                    {
                        "owasp_id": t.get("id"),
                        "name": t.get("name"),
                        "prompt": prompt,
                        "response": response,
                        "risk_score": random.randint(0, 100),
                    }
                )

    print("Done:", args.out)


if __name__ == "__main__":
    main()

