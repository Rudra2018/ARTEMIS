import os
import sys

import pandas as pd
from notion_client import Client


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python scripts/sync_to_notion.py <csv_path>")
        sys.exit(1)

    token = os.environ["NOTION_TOKEN"]
    database_id = os.environ["NOTION_DATABASE_ID"]
    df = pd.read_csv(sys.argv[1])

    notion = Client(auth=token)
    for _, row in df.iterrows():
        notion.pages.create(
            parent={"database_id": database_id},
            properties={
                "PromptID": {"number": int(row.get("id", 0))},
                "Provider": {"select": {"name": str(row.get("provider", ""))}},
                "Risk": {"number": float(row.get("risk_score", 0))},
                "DLP": {"checkbox": bool(row.get("dlp_flag", False))},
                "Prompt": {
                    "title": [
                        {"text": {"content": str(row.get("prompt", ""))}}
                    ]
                },
            },
        )

    print("Synced rows:", len(df))


if __name__ == "__main__":
    main()
