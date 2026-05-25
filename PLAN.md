# nleash Development Roadmap

This document outlines the strategic plan followed to transform `nleash` from a prototype into a production-grade system utility.

## Phase 1: Architectural Refactoring (The Principal Engineer Perspective)
- **Goal:** Improve maintainability and testability.
- **Actions:**
    - Extract orchestration logic from a monolithic `main` into a dedicated `LeashManager` class.
    - Decouple CLI parsing from implementation details.
    - Modularize Traffic Control (`TC`) and `Cgroup` logic into cohesive units.

## Phase 2: System Reliability & Safety
- **Goal:** Ensure the tool is safe for multi-user/production environments.
- **Actions:**
    - **State Locking:** Implement advisory `flock()` on the state database to prevent race conditions.
    - **Idempotency:** Modify TC setup to detect and reuse existing root qdiscs ("The Second Leash Bug").
    - **Robust Identity:** Strengthen process verification using start-time and boot-id validation.

## Phase 3: Observability
- **Goal:** Provide administrators with real-time insight into enforcement.
- **Actions:**
    - Implement the `--stats` flag.
    - Extract real-time throughput (bps), packet counts, and drop metrics from the kernel.
    - Support `--json` output for monitoring integration.

## Phase 4: Deployment Ergonomics (The Architect's Path)
- **Goal:** Eliminate heavy runtime dependencies and simplify distribution.
- **Actions:**
    - **libbpf Integration:** Transition from shelling out to `bpftool` to using the direct C++ API.
    - **CO-RE (Compile Once - Run Everywhere):** Implement `vmlinux.h` and BPF skeletons to embed bytecode.
    - **Zero-Dependency Binary:** Ensure end-user machines don't need `clang` or kernel headers.

## Phase 5: Hardware & Distribution Compatibility
- **Goal:** Ensure "it just works" on modern distributions like Fedora.
- **Actions:**
    - **Cgroup ID Fallbacks:** Implement `name_to_handle_at` and `stat()` support for systems missing `cgroup.id` files.
    - **Classification Robustness:** Refine BPF matching logic to use 32-bit inode keys to bypass 64-bit mount-ID mismatches.
    - **Default Class Alignment:** Ensure unclassified system traffic is never accidentally throttled or reset.
