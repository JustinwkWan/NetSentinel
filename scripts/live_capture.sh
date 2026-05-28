#!/usr/bin/env bash
# live_capture.sh — capture live traffic into a rolling pcapng ring buffer.
#
# Uses dumpcap's built-in ring buffer:
#   - rotates to a new file every CAPTURE_DURATION seconds
#   - keeps at most CAPTURE_FILES files (oldest auto-deleted)
#
# So with the defaults (60s × 10 files), you have a continuously updating
# 10-minute sliding window of pcapng files in data/pcaps/.
#
# Env vars (all optional):
#   CAPTURE_IFACE        network interface (default: en0)
#   CAPTURE_DURATION     seconds per file (default: 60)
#   CAPTURE_FILES        max files retained (default: 10)
#   CAPTURE_DIR          output dir (default: <repo>/data/pcaps)
#   CAPTURE_PREFIX       file prefix (default: live)
#   DUMPCAP              path to dumpcap binary (auto-detected if unset)
#
# Usage:
#   sudo ./scripts/live_capture.sh
#   CAPTURE_IFACE=en1 CAPTURE_DURATION=30 sudo ./scripts/live_capture.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

CAPTURE_IFACE="${CAPTURE_IFACE:-en0}"
CAPTURE_DURATION="${CAPTURE_DURATION:-60}"
CAPTURE_FILES="${CAPTURE_FILES:-10}"
CAPTURE_DIR="${CAPTURE_DIR:-$REPO_ROOT/data/pcaps}"
CAPTURE_PREFIX="${CAPTURE_PREFIX:-live}"

# Locate dumpcap
if [[ -z "${DUMPCAP:-}" ]]; then
  for candidate in \
    "$(command -v dumpcap 2>/dev/null || true)" \
    "/opt/homebrew/bin/dumpcap" \
    "/usr/local/bin/dumpcap" \
    "/Applications/Wireshark.app/Contents/MacOS/dumpcap"; do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
      DUMPCAP="$candidate"
      break
    fi
  done
fi

if [[ -z "${DUMPCAP:-}" || ! -x "$DUMPCAP" ]]; then
  echo "ERROR: dumpcap not found. Install Wireshark or set DUMPCAP=/path/to/dumpcap" >&2
  exit 1
fi

mkdir -p "$CAPTURE_DIR"

OUT="$CAPTURE_DIR/${CAPTURE_PREFIX}.pcapng"

echo "[live_capture] dumpcap: $DUMPCAP"
echo "[live_capture] interface: $CAPTURE_IFACE"
echo "[live_capture] rotating every ${CAPTURE_DURATION}s, keeping ${CAPTURE_FILES} files"
echo "[live_capture] writing: ${OUT} (rotated as ${CAPTURE_PREFIX}_<NNNNN>_<timestamp>.pcapng)"
echo

# -i interface  -b duration:Ns  -b files:N  -w output (rotation template)
# dumpcap writes pcapng by default. macOS BPF may need sudo or chmod +r /dev/bpf*.
exec "$DUMPCAP" \
  -i "$CAPTURE_IFACE" \
  -b "duration:${CAPTURE_DURATION}" \
  -b "files:${CAPTURE_FILES}" \
  -w "$OUT"
