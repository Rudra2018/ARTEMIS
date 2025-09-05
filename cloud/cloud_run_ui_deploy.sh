#!/usr/bin/env bash
set -euo pipefail
cd dashboards
npm install && npm run build
cd ..
gcloud builds submit --tag gcr.io/$GOOGLE_CLOUD_PROJECT/ai-llm-ui
gcloud run deploy ai-llm-ui --image gcr.io/$GOOGLE_CLOUD_PROJECT/ai-llm-ui --region=${REGION:-us-central1} --platform=managed --allow-unauthenticated
