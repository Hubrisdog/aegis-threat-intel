#!/bin/bash
# Aegis Threat Intelligence Platform
# Manages both server (Bun) and client (Vite) processes
#
# Ports are read from .env at the project root:
#   PORT          — API server port (default: 4001)
#   CLIENT_PORT   — Vite dev server port (default: 5174)
# Override per-host by setting these in .env without modifying this script.

DASHBOARD_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="${HOME}/.aegis-intel/logs"
mkdir -p "$LOG_DIR"

# Source .env so this script sees PORT/CLIENT_PORT
ENV_FILE="$DASHBOARD_DIR/.env"
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi
PORT="${PORT:-4001}"
CLIENT_PORT="${CLIENT_PORT:-5174}"

SERVER_PID_FILE="/tmp/aegis-server.pid"
CLIENT_PID_FILE="/tmp/aegis-client.pid"

start() {
  echo "Starting Aegis Threat Intel..."

  # Start server
  cd "$DASHBOARD_DIR/apps/server"
  bun run dev >> "$LOG_DIR/server.log" 2>&1 &
  echo $! > "$SERVER_PID_FILE"
  echo "  Server PID: $(cat $SERVER_PID_FILE)"

  # Wait for server
  for i in {1..15}; do
    curl -s "http://localhost:${PORT}/health" >/dev/null 2>&1 && break
    sleep 1
  done

  # Start client via Bun
  cd "$DASHBOARD_DIR/apps/client"
  bun ./node_modules/.bin/vite --port "$CLIENT_PORT" --host 0.0.0.0 >> "$LOG_DIR/client.log" 2>&1 &
  echo $! > "$CLIENT_PID_FILE"
  echo "  Client PID: $(cat $CLIENT_PID_FILE)"

  echo ""
  echo "Aegis Threat Intel is running:"
  echo "  Dashboard: http://localhost:${CLIENT_PORT}"
  echo "  API:       http://localhost:${PORT}"
  echo "  Health:    http://localhost:${PORT}/health"
}

stop() {
  echo "Stopping Aegis Threat Intel..."
  for pid_file in "$SERVER_PID_FILE" "$CLIENT_PID_FILE"; do
    if [ -f "$pid_file" ]; then
      pid=$(cat "$pid_file")
      if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null
        echo "  Stopped PID $pid"
      fi
      rm -f "$pid_file"
    fi
  done
  # Clean up any stragglers
  pkill -f "aegis-intel.*server" 2>/dev/null
  pkill -f "vite.*${CLIENT_PORT}" 2>/dev/null
  echo "Done."
}

status() {
  local running=0
  for pid_file in "$SERVER_PID_FILE" "$CLIENT_PID_FILE"; do
    if [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
      running=$((running + 1))
    fi
  done
  if [ "$running" -eq 2 ]; then
    echo "Aegis Threat Intel is running (server + client)"
    curl -s "http://localhost:${PORT}/health" | python3 -m json.tool 2>/dev/null
  elif [ "$running" -gt 0 ]; then
    echo "Aegis Threat Intel is partially running ($running/2 processes)"
  else
    echo "Aegis Threat Intel is stopped"
  fi
}

logs() {
  echo "=== Server Log (last 30 lines) ==="
  tail -30 "$LOG_DIR/server.log" 2>/dev/null || echo "No server logs"
  echo ""
  echo "=== Client Log (last 10 lines) ==="
  tail -10 "$LOG_DIR/client.log" 2>/dev/null || echo "No client logs"
}

case "${1:-}" in
  start)   start ;;
  stop)    stop ;;
  restart) stop; sleep 1; start ;;
  status)  status ;;
  logs)    logs ;;
  *)
    echo "Usage: $0 {start|stop|restart|status|logs}"
    exit 1
    ;;
esac
