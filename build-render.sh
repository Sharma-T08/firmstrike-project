#!/usr/bin/env bash
set -e

echo "Installing Node dependencies..."
pnpm install --frozen-lockfile

echo "Installing Python dependencies..."
python3 -m pip install --upgrade pip
python3 -m pip install -r python-scanner/requirements.txt

echo "Building backend..."
pnpm --filter backend run build

echo "Build complete."
