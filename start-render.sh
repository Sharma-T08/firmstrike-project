#!/usr/bin/env bash
set -e

echo "Starting Python scanner..."
python -m uvicorn python-scanner.app:app --host 127.0.0.1 --port 8010 &

echo "Starting Node backend..."
exec pnpm --filter backend start
