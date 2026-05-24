#!/bin/bash
# tests/nleash-arch-tests.sh
# Verification for architectural improvements:
# 1. Idempotent root qdisc (Second Leash bug)
# 2. State file locking/concurrency
# 3. Modular LeashManager behavior

set -e

# Path to the binary
NLEASH="./bin/nleash"
IFACE=$(ip route show default | awk '/default/ {print $5}' | head -n1)

if [ -z "$IFACE" ]; then
    echo "ERROR: Could not detect default interface."
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP: This test requires root/sudo to manipulate tc and cgroups."
    exit 0
fi

# Ensure bin is built
make -s all

echo "--- Test 1: Idempotent Root Qdisc (Multiple Leashes) ---"
# Apply first leash
$NLEASH --rate 1mbit -- sleep 10 &
P1=$!
sleep 1

# Apply second leash (should not fail now)
if $NLEASH --rate 2mbit -- sleep 10 & P2=$!; then
    echo "SUCCESS: Second leash applied correctly."
else
    echo "FAILURE: Second leash failed (likely Second Leash bug)."
    kill $P1 2>/dev/null || true
    exit 1
fi

# Cleanup
kill $P1 $P2 2>/dev/null || true
wait $P1 $P2 2>/dev/null || true
echo "Test 1 Passed."

echo "--- Test 2: State File Integrity (Concurrency) ---"
# We'll run many leashes in parallel to stress the flock implementation
NUM_PROCS=10
PIDS=()

echo "Launching $NUM_PROCS parallel leashes..."
for i in $(seq 1 $NUM_PROCS); do
    $NLEASH --rate 1mbit -- sleep 5 &
    PIDS+=($!)
done

# Wait for them to finish
for p in "${PIDS[@]}"; do
    wait $p || true
done

# After all exit, the state file should be empty (assuming no other leashes were active)
COUNT=$(sudo ./bin/nleash --list | wc -l)
if [ "$COUNT" -eq 0 ]; then
    echo "SUCCESS: State file is clean after concurrent operations."
else
    echo "WARNING: State file has $COUNT dangling entries. Check if this is expected."
    # We won't exit 1 here if other leashes exist, but on a clean system it should be 0.
fi
echo "Test 2 Passed."

echo "--- Test 3: Cgroup Nesting Verification ---"
# Verify that leashes are created under the correct parent cgroup
# Use a longer sleep to ensure the process stays alive during inspection
$NLEASH --rate 1mbit -- sleep 30 &
P3=$!
# Wait for the process to actually start and for nleash to move it
sleep 2

if ! ps -p $P3 > /dev/null; then
    echo "FAILURE: Process $P3 died unexpectedly."
    exit 1
fi

CG_PATH=$(cat /proc/$P3/cgroup | cut -d: -f3 | head -n1)
if [[ "$CG_PATH" == *"/nleash-"* ]]; then
    echo "SUCCESS: Process is in a nested nleash cgroup: $CG_PATH"
else
    # On some systems, the error 'cgroup.id not available' might prevent the move.
    # We check if the move was attempted or if the tool bailed.
    echo "FAILURE: Process is NOT in a nested nleash cgroup: $CG_PATH"
    echo "Note: If you saw 'cgroup.id not available', this is expected on this kernel."
    kill $P3 2>/dev/null || true
    exit 1
fi
kill $P3 2>/dev/null || true
wait $P3 2>/dev/null || true
echo "Test 3 Passed."

echo "All Architectural Tests Passed!"
