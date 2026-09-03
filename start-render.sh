#!/usr/bin/env bash
set -e

echo "Starting Python scanner..."
python -m uvicorn app:app --app-dir python-scanner --host 127.0.0.1 --port 8010 &

echo "Starting Node backend..."
exec pnpm --filter backend start
