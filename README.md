# 🤖 AI Chatbot Security Tester — Ultimate Edition

Test the security of **Google Gemini**, **Meta AI**, **ChatGPT**, **Claude**, and **HackerOne Hai**.

## ✨ Features
- 🛡️ OWASP **LLM Top 10** test coverage
- 🧠 Hallucination and data‑leak detection with risk scoring
- 🧪 Gerake-based fuzzing
- 📊 React dashboard (`dashboards/`)
- ☁️ BigQuery + Notion export
- 🔁 GitHub Actions CI/CD

## 🧱 Architecture

User ─▶ Prompt Runner ─▶ Provider (Gemini / GPT / Claude / Meta / Hai)
│
▼
AI Engines (Risk / DLP / Halluc.)
│
Reports + Sync
┌──────────┴──────────┐
▼                     ▼
BigQuery              Notion

### Architecture Diagram

![Architecture](ai_chatbot_security_architecture.png)

## 🛠️ Local Setup

### Backend
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r scripts/requirements.txt
```

### Frontend (Dashboard)
```bash
cd dashboards
npm install
npm run dev
```

### Environment Variables (`.env` in repo root)
```bash
GOOGLE_APPLICATION_CREDENTIALS=/absolute/path/to/key.json
NOTION_TOKEN=your_secret_notion_token
NOTION_DATABASE_ID=your_notion_database_id
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

## 🚀 Usage

### 1. Run a batch of prompts
```bash
python scripts/batch_runner.py --provider gpt --out reports/results.csv --count 5
```

### 2. OWASP LLM Top 10 tests
```bash
python scripts/run_owasp_tests.py --out reports/owasp_results.csv
```

### 3. Gerake fuzz testing
```bash
python scripts/run_gerake_tests.py --provider claude --testcases examples/gerake_suite.yaml
```
`examples/gerake_suite.yaml` ships with prompt-injection, PII exfiltration, and jailbreak
payloads targeting **Gemini**, **GPT**, **Claude**, **Meta AI Studio**, and **HackerOne Hai**.

### 4. Sync results to data sinks
```bash
python scripts/sync_to_bigquery.py reports/results.csv
python scripts/sync_to_notion.py reports/results.csv
```

### 5. Trigger Slack alert (optional)
```bash
python scripts/notify_slack.py --file reports/results.csv
```

## ☁️ Cloud & CI/CD
- GitHub Actions run tests on push
- `dashboards/` can be deployed to Vercel
- `cloud/cloud_run_ui_deploy.sh` deploys dashboard to Cloud Run

## 📎 Notes
- Ensure API keys and provider tokens are valid
- Only test providers with explicit permission for responsible AI research
