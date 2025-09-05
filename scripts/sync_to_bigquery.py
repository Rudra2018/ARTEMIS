import os, sys, pandas as pd
from google.cloud import bigquery
def main():
if len(sys.argv) < 2:
print("Usage: python scripts/sync_to_bigquery.py <csv_path>")
sys.exit(1)
csv_path = sys.argv[1]
df = pd.read_csv(csv_path)

project = os.environ.get("GOOGLE_CLOUD_PROJECT")
dataset = os.environ.get("BQ_DATASET", "ai_tester")
table = os.environ.get("BQ_TABLE", "results")

client = bigquery.Client(project=project)
table_id = f"{project}.{dataset}.{table}"
client.create_dataset(dataset, exists_ok=True)
job = client.load_table_from_dataframe(df, table_id)
job.result()
print("Loaded rows:", len(df), "to", table_id)
if name == "main":
main()
