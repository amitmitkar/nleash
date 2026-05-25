#!/bin/sh
set -eu

say() { printf '%s\n' "$*"; }

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
BIN="$ROOT_DIR/bin/nleash"
HELPER="$ROOT_DIR/bin/nleash-helper"

if [ ! -x "$BIN" ]; then
  say "SKIP: $BIN not found or not executable. Run 'make' first."
  exit 0
fi

# Privileges: either root, or setuid helper.
if [ "$(id -u)" -ne 0 ]; then
  if [ ! -x "$HELPER" ]; then
    say "SKIP: $HELPER not found. Install helper or run as root."
    exit 0
  fi
  helper_uid="$(stat -c '%u' "$HELPER" 2>/dev/null || echo 1)"
  helper_mode="$(stat -c '%a' "$HELPER" 2>/dev/null || echo 0)"
  mode_len=$(printf '%s' "$helper_mode" | wc -c | tr -d ' ')
  if [ "$mode_len" -lt 4 ]; then
    say "SKIP: $HELPER is not setuid root. Run as root or setuid helper."
    exit 0
  fi
  setuid_digit=$(printf '%s' "$helper_mode" | cut -c1)
  case "$setuid_digit" in
    4|5|6|7) :;;
    *)
      say "SKIP: $HELPER is not setuid root. Run as root or setuid helper."
      exit 0
      ;;
  esac
  if [ "$helper_uid" -ne 0 ]; then
    say "SKIP: $HELPER is not owned by root."
    exit 0
  fi
fi

# cgroup v2 + bpffs checks.
if [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
  say "SKIP: cgroup v2 not detected at /sys/fs/cgroup."
  exit 0
fi
if [ ! -d /sys/fs/bpf ]; then
  say "SKIP: bpffs not mounted at /sys/fs/bpf."
  exit 0
fi

say "Running nleash list tests..."
"$BIN" --list >/dev/null
"$BIN" --list --json >/dev/null

if [ "${NLEASH_ACTIVE:-0}" = "1" ]; then
  say "Running active leash tests..."
  sleeper_pid=""
  cleanup_active() {
    if [ -n "${sleeper_pid}" ]; then
      "$BIN" --pid "${sleeper_pid}" --clear >/dev/null 2>&1 || true
      kill "${sleeper_pid}" >/dev/null 2>&1 || true
      wait "${sleeper_pid}" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup_active EXIT INT TERM

  sleep 5 &
  sleeper_pid="$!"

  "$BIN" --pid "${sleeper_pid}" --rate 10mbit >/dev/null
  "$BIN" --list >/dev/null
  "$BIN" --pid "${sleeper_pid}" --clear >/dev/null

  wait "${sleeper_pid}" >/dev/null 2>&1 || true
  sleeper_pid=""
  trap - EXIT INT TERM
  say "Active leash tests completed."
fi

if [ "${NLEASH_NETTEST:-0}" = "1" ]; then
  say "Running throttled-download test (requires Internet)..."
  if ! command -v curl >/dev/null 2>&1; then
    say "SKIP: curl not found."
  else
    rate="${NLEASH_RATE:-1mbit}"
    url="${NLEASH_URL:-https://speed.cloudflare.com/__down?bytes=2000000}"
    cap="${NLEASH_CAP_SEC:-30}"

    start=$(date +%s)
    "$BIN" --rate "$rate" -- \
      curl -s -L -o /dev/null --max-time "$cap" "$url" >/dev/null 2>&1 || true
    end=$(date +%s)
    elapsed=$((end - start))

    # At 1mbit, 2MB should take ~16s. Anything under 5s means no throttling.
    if [ "$elapsed" -lt 5 ]; then
      say "FAIL: throttled download finished in ${elapsed}s (expected >= 5s at ${rate}). No throttling."
      exit 1
    fi
    say "Throttled download took ${elapsed}s at ${rate}."
  fi
fi

say "OK: nleash smoke checks passed."
