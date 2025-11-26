#!/usr/bin/env bash
set -euo pipefail

echo "Starting Orchestrator (Port 8032)..."
uvicorn app:app --host 0.0.0.0 --port 8032 --log-level info &
ORCH_PID=$!

echo "Starting Detector Agent (Port 8033)..."
uvicorn detector:app --host 0.0.0.0 --port 8033 --log-level info &
DETECTOR_PID=$!

wait -n $ORCH_PID $DETECTOR_PID
EXIT_CODE=$?

kill -TERM $ORCH_PID $DETECTOR_PID 2>/dev/null || true
exit $EXIT_CODE