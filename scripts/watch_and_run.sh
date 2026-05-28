#!/usr/bin/env bash
# watch_and_run.sh — watch the capture dir for completed rotations and run
# the NetSentinel pipeline on each one.
#
# A dumpcap ring-buffer file is "closed" once a newer-numbered file exists.
# We sort by name (the rotation index is zero-padded), skip the highest-
# numbered file (still being written), and fire /runs for the rest.
#
# Env vars (all optional):
#   API_URL              backend base URL (default: http://localhost:8765)
#   CAPTURE_DIR          dir to watch (default: <repo>/data/pcaps)
#   CAPTURE_PREFIX       file prefix to match (default: live)
#   DETECTOR             "stub" or "lstm" (default: lstm)
#   POLL_INTERVAL        seconds between checks (default: 5)
#
# Usage:
#   ./scripts/watch_and_run.sh
#   DETECTOR=stub ./scripts/watch_and_run.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

API_URL="${API_URL:-http://localhost:8765}"
CAPTURE_DIR="${CAPTURE_DIR:-$REPO_ROOT/data/pcaps}"
CAPTURE_PREFIX="${CAPTURE_PREFIX:-live}"
DETECTOR="${DETECTOR:-lstm}"
POLL_INTERVAL="${POLL_INTERVAL:-5}"

PROCESSED_FILE="$(mktemp -t netsentinel_processed.XXXX)"
trap 'rm -f "$PROCESSED_FILE"' EXIT

echo "[watch_and_run] watching: $CAPTURE_DIR/${CAPTURE_PREFIX}_*.pcapng"
echo "[watch_and_run] API: $API_URL  detector: $DETECTOR  poll: ${POLL_INTERVAL}s"
echo

# Health check (warn but don't fail — the API may come up later)
if ! curl -sf "${API_URL}/health" > /dev/null; then
  echo "[watch_and_run] WARN: API not reachable at $API_URL"
fi

while true; do
  # List rotated files sorted by name. dumpcap zero-pads the index, so name
  # sort == chronological. The LAST one is being written; everything earlier
  # is closed. Use a sentinel to find the latest file (portable to bash 3.2).
  sorted_list=$(find "$CAPTURE_DIR" -maxdepth 1 -type f \
                  -name "${CAPTURE_PREFIX}_*.pcapng" 2>/dev/null | sort)
  count=$(printf '%s\n' "$sorted_list" | grep -c . || true)

  if [[ "$count" -gt 1 ]]; then
    # Everything except the last line is a closed rotation
    closed=$(printf '%s\n' "$sorted_list" | sed '$d')
    while IFS= read -r f; do
      [[ -z "$f" ]] && continue
      name="$(basename "$f")"
      if ! grep -Fxq "$name" "$PROCESSED_FILE" 2>/dev/null; then
        echo "[watch_and_run] $(date +%H:%M:%S) → trigger run on $name"
        resp=$(curl -sf -X POST "${API_URL}/runs" \
                    -H "Content-Type: application/json" \
                    -d "{\"pcap_name\":\"${name}\",\"detector\":\"${DETECTOR}\"}" \
                    || true)
        if [[ -n "$resp" ]]; then
          job_id=$(echo "$resp" | sed -n 's/.*"job_id":"\([^"]*\)".*/\1/p')
          echo "[watch_and_run]   job_id=${job_id:-?}"
          echo "$name" >> "$PROCESSED_FILE"
        else
          echo "[watch_and_run]   ERROR: API call failed; will retry next tick"
        fi
      fi
    done <<< "$closed"
  fi

  sleep "$POLL_INTERVAL"
done
