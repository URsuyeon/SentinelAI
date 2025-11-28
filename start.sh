#!/usr/bin/env bash
set -euo pipefail

echo "Starting Orchestrator (Port 8032)..."
uvicorn orchestrator:app --host 0.0.0.0 --port 8032 --log-level info &
ORCH_PID=$!

echo "Starting Detector Agent (Port 8033)..."
uvicorn detector:app --host 0.0.0.0 --port 8033 --log-level info &
DETECTOR_PID=$!

while true; do
  if ! kill -0 "$ORCH_PID" 2>/dev/null; then
    echo "Orchestrator exited."
    kill -TERM "$DETECTOR_PID" 2>/dev/null || true
    wait "$ORCH_PID" 2>/dev/null || true
    break
  fi
  if ! kill -0 "$DETECTOR_PID" 2>/dev/null; then
    echo "Detector exited."
    kill -TERM "$ORCH_PID" 2>/dev/null || true
    wait "$DETECTOR_PID" 2>/dev/null || true
    break
  fi
  sleep 1
done