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

# Check privileges: either root, or setuid helper available.
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

# Basic tooling checks.
for cmd in tc ip modprobe; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    say "SKIP: required tool '$cmd' not found in PATH."
    exit 0
  fi
done

# cgroup v2 check.
if [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
  say "SKIP: cgroup v2 not detected at /sys/fs/cgroup."
  exit 0
fi
if [ ! -f /sys/fs/cgroup/cgroup.id ]; then
  say "SKIP: cgroup.id not available (kernel missing cgroup.id support)."
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
  say "Running network exercise with nc (best-effort)..."
  if ! command -v nc >/dev/null 2>&1; then
    say "SKIP: nc not found; set NLEASH_NETTEST=1 requires nc."
  elif [ -z "${NLEASH_NC_HOST:-}" ] || [ -z "${NLEASH_NC_PORT:-}" ]; then
    say "SKIP: set NLEASH_NC_HOST and NLEASH_NC_PORT for nc test."
  else
    bytes="${NLEASH_NET_BYTES:-1048576}"
    # Send a fixed amount of data to a listener using nc.
    if "$BIN" --rate 200kbit -- sh -c "head -c ${bytes} /dev/zero | nc -w 5 \"$NLEASH_NC_HOST\" \"$NLEASH_NC_PORT\" >/dev/null 2>&1"; then
      say "Network exercise completed."
    else
      say "SKIP: network exercise failed (no listener or blocked)."
    fi
  fi
fi

say "OK: nleash smoke checks passed."
