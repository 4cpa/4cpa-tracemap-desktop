#!/bin/bash
# Startet/stoppt TraceMap. Aufruf: start.sh [start|stop|status]
cd "$(dirname "$0")" || exit 1
PORT=8765
URL="http://127.0.0.1:$PORT"

running() { curl -s -m 2 -o /dev/null "$URL/api/results"; }

case "${1:-start}" in
  status) running && echo running || echo stopped ;;
  stop)   pkill -f "uvicorn app:app" ; echo stopped ;;
  start)
    if ! running; then
      nohup .venv/bin/uvicorn app:app --host 127.0.0.1 --port $PORT > server.log 2>&1 &
      for _ in $(seq 1 20); do running && break; sleep 0.5; done
    fi
    open "$URL"
    ;;
esac
