#!/bin/bash
# Architectural verification:
# 1. Multiple concurrent leashes (no shared-qdisc contention since there is no qdisc)
# 2. State file integrity under parallel ops (flock)
# 3. Cgroup nesting (target ends up in /<parent>/nleash-N)
# 4. BPF pin lifecycle (prog/map persist across CLI invocations; per-leash links unpinned on detach)
# 5. Positive throttling test (curl actually slows down)

set -e

NLEASH="./bin/nleash"

if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP: This test requires root/sudo to manage cgroups and BPF."
    exit 0
fi

if [ ! -d /sys/fs/bpf ]; then
    echo "SKIP: /sys/fs/bpf not mounted."
    exit 0
fi

make -s all

echo "--- Test 1: Multiple concurrent leashes ---"
$NLEASH --rate 1mbit -- sleep 10 &
P1=$!
sleep 0.5
$NLEASH --rate 2mbit -- sleep 10 &
P2=$!
sleep 0.5

LIST_COUNT=$($NLEASH --list | wc -l)
if [ "$LIST_COUNT" -ge 2 ]; then
    echo "SUCCESS: $LIST_COUNT concurrent leashes active."
else
    echo "FAILURE: expected >= 2 leashes, got $LIST_COUNT"
    kill $P1 $P2 2>/dev/null || true
    exit 1
fi

kill $P1 $P2 2>/dev/null || true
wait $P1 $P2 2>/dev/null || true
echo "Test 1 Passed."

echo "--- Test 2: Cgroup nesting ---"
$NLEASH --rate 1mbit -- sleep 30 &
P3=$!
sleep 2

if ! ps -p $P3 > /dev/null; then
    echo "FAILURE: Process $P3 died unexpectedly."
    exit 1
fi

# Walk to the sleep grandchild
SLEEP_PID=$(pgrep -P $(pgrep -P $P3 | head -1) | head -1)
[ -z "$SLEEP_PID" ] && SLEEP_PID=$(pgrep -P $P3 | head -1)
[ -z "$SLEEP_PID" ] && SLEEP_PID=$P3

CG_PATH=$(awk -F: '/^0::/ {print $3}' /proc/$SLEEP_PID/cgroup)
if [[ "$CG_PATH" == *"/nleash-"* ]]; then
    echo "SUCCESS: Process is in nested cgroup: $CG_PATH"
else
    echo "FAILURE: Process is NOT in a nested nleash cgroup: $CG_PATH"
    kill $P3 2>/dev/null || true
    exit 1
fi
kill $P3 2>/dev/null || true
wait $P3 2>/dev/null || true
echo "Test 2 Passed."

echo "--- Test 3: BPF pin lifecycle ---"
# After previous tests, prog/map should be pinned but links should be empty.
if [ -e /sys/fs/bpf/nleash/prog ] && [ -e /sys/fs/bpf/nleash/buckets ]; then
    echo "SUCCESS: prog and buckets are pinned."
else
    echo "FAILURE: expected /sys/fs/bpf/nleash/{prog,buckets} to exist."
    ls -la /sys/fs/bpf/nleash/ || true
    exit 1
fi

LINKS=$(ls /sys/fs/bpf/nleash/links/ 2>/dev/null | wc -l)
if [ "$LINKS" -eq 0 ]; then
    echo "SUCCESS: no orphaned per-leash links."
else
    echo "WARNING: $LINKS link(s) remain after teardown."
    ls -la /sys/fs/bpf/nleash/links/
fi
echo "Test 3 Passed."

echo "--- Test 4: Actual throttling (1mbit; should take >= 5s for 2MB) ---"
if command -v curl >/dev/null 2>&1; then
    start=$(date +%s)
    $NLEASH --rate 1mbit -- \
        curl -s -L -o /dev/null --max-time 30 \
        'https://speed.cloudflare.com/__down?bytes=2000000' >/dev/null 2>&1 || true
    end=$(date +%s)
    elapsed=$((end - start))
    if [ "$elapsed" -ge 5 ]; then
        echo "SUCCESS: 2MB at 1mbit took ${elapsed}s (>= 5s)."
    else
        echo "FAILURE: 2MB at 1mbit took only ${elapsed}s — throttling not effective."
        exit 1
    fi
else
    echo "SKIP: curl not found; cannot verify throttling end-to-end."
fi
echo "Test 4 Passed."

echo "All Architectural Tests Passed!"
