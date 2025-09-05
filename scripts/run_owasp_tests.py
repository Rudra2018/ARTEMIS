import yaml, csv, argparse, time, random, pathlib
def mock_call(prompt):
time.sleep(0.02)
return f"mock: {prompt}"

def main():
ap = argparse.ArgumentParser()
ap.add_argument("--tests", default="models/owasp_llm_top10_tests.yaml")
ap.add_argument("--out", default="reports/owasp_results.csv")
args = ap.parse_args()

data = yaml.safe_load(open(args.tests))
pathlib.Path(args.out).parent.mkdir(parents=True, exist_ok=True)
with open(args.out, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["owasp_id","name","prompt","response","risk_score"])
    w.writeheader()
    for t in data:
        for p in t["prompts"]:
            resp = mock_call(p)
            w.writerow({"owasp_id": t["id"], "name": t["name"], "prompt": p, "response": resp, "risk_score": random.randint(0,100)})
print("Done:", args.out)
if name == "main":
main()
