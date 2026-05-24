# Kernel 6.0+ Migration Guide

## Overview

Starting with Linux kernel ~5.18, the `CONFIG_NET_CLS_CGROUP` option was deprecated, and it has been completely removed in kernel 6.x. This breaks the original `nleash` implementation which relied on the `cls_cgroup` traffic control filter.

This document explains the changes made to support both old and new kernels.

## Changes Summary

### What Changed

1. **Hybrid Filter Detection**: `nleash` now automatically detects which traffic control method to use:
   - **Older kernels (< 6.0)**: Uses traditional `cls_cgroup` filter
   - **Newer kernels (≥ 6.0)**: Uses eBPF-based classifier

2. **eBPF Implementation**: Added a small eBPF program ([src/tc_cgroup.bpf.c](src/tc_cgroup.bpf.c)) that replicates `cls_cgroup` functionality using modern kernel features.

3. **Runtime Detection**: The tool automatically selects the appropriate method at runtime, providing seamless backwards compatibility.

## Kernel Compatibility

| Distribution | Kernel Version | Method Used | Status |
|-------------|---------------|-------------|---------|
| RHEL 7 | 3.10.x | cls_cgroup | ✅ Supported |
| RHEL 8 | 4.18.x | cls_cgroup | ✅ Supported |
| RHEL 9 | 5.14.x | cls_cgroup | ✅ Supported |
| RHEL 10 | 6.12.x | eBPF | ✅ Supported |
| Fedora 40+ | 6.x+ | eBPF | ✅ Supported |
| Ubuntu 22.04 | 5.15.x | cls_cgroup | ✅ Supported |
| Ubuntu 24.04+ | 6.x+ | eBPF | ✅ Supported |

## New Requirements for Kernel 6.0+

On kernels 6.0 and newer, you need:

1. **clang** (version 10+) - for compiling eBPF programs
2. **bpftool** - for managing eBPF maps (part of `linux-tools` package)
3. **Kernel with eBPF support** - `bpf_skb_cgroup_id()` helper (kernel ≥ 4.18)

### Installing Requirements

**RHEL/Fedora:**
```bash
sudo dnf install clang bpftool kernel-devel
```

**Ubuntu/Debian:**
```bash
sudo apt install clang linux-tools-$(uname -r) linux-headers-$(uname -r)
```

## How It Works

### Detection Logic

On startup, `nleash` performs the following checks:

1. **Try cls_cgroup first** (for backwards compatibility):
   - Attempts to load `cls_cgroup` kernel module
   - Checks `/sys/module/cls_cgroup` exists
   - Verifies `CONFIG_NET_CLS_CGROUP=y` in kernel config

2. **Fall back to eBPF** if cls_cgroup unavailable:
   - Checks for `clang` availability
   - Verifies kernel version ≥ 4.18
   - Compiles eBPF program if not already compiled
   - Loads eBPF classifier via `tc filter add ... bpf`

### eBPF Implementation Details

The eBPF approach works as follows:

1. **Compilation**: [src/tc_cgroup.bpf.c](src/tc_cgroup.bpf.c) is compiled to BPF bytecode
2. **Loading**: BPF program is loaded as a `tc` filter on the network interface
3. **Map Management**: A BPF hash map stores cgroup ID → classid mappings
4. **Classification**: For each packet, the BPF program:
   - Retrieves the originating cgroup ID using `bpf_skb_cgroup_id()`
   - Looks up the classid in the map
   - Sets the packet priority for HTB qdisc classification

## Building

The Makefile automatically compiles the eBPF program if `clang` is available:

```bash
make clean
make
```

If `clang` is not available, you'll see a warning:
```
Warning: clang not found, skipping eBPF compilation (required for kernel 6.0+)
```

This means `nleash` will only work on older kernels with `cls_cgroup` support.

## Testing

To verify which method is being used, run with elevated privileges:

```bash
sudo ./bin/nleash --list
```

The tool will automatically detect and use the appropriate method. Check system logs for details:

```bash
# For cls_cgroup method
lsmod | grep cls_cgroup

# For eBPF method
tc filter show dev <interface>
bpftool prog list
bpftool map list
```

## Troubleshooting

### "No suitable TC filter method available"

This error means neither `cls_cgroup` nor eBPF is available. Check:

1. Kernel version: `uname -r`
2. cls_cgroup availability: `modprobe cls_cgroup`
3. clang availability: `clang --version`
4. Kernel eBPF support: `zgrep CONFIG_BPF /proc/config.gz`

### "failed to compile eBPF program"

Ensure you have:
- `clang` installed
- Kernel headers installed: `linux-headers-$(uname -r)`
- BPF target support: `clang -target bpf -v`

### "failed to load eBPF classifier"

Check:
- HTB qdisc is configured: `tc qdisc show`
- No conflicting tc filters: `tc filter show`
- BPF filesystem mounted: `mount | grep /sys/fs/bpf`

### "bpftool required"

Install bpftool:
- RHEL/Fedora: `sudo dnf install bpftool`
- Ubuntu/Debian: `sudo apt install linux-tools-$(uname -r)`

## Design Trade-offs

### Why Not Pure eBPF?

We could have migrated entirely to eBPF, but chose a hybrid approach because:

1. **Backwards Compatibility**: Works on RHEL 7/8/9 without changes
2. **Simplicity**: No new dependencies on older systems
3. **Gradual Migration**: Teams can upgrade at their own pace

### Why Not Alternative Approaches?

Other options considered:

- **cgroup v2 net_cls controller**: Limited functionality, not widely available
- **IFB + ingress**: Complex setup, doesn't solve the egress problem
- **Pure libbpf**: Adds significant complexity and build dependencies

## References

- [Linux cls_cgroup deprecation discussion](https://lore.kernel.org/netdev/)
- [eBPF and tc filtering](https://docs.kernel.org/bpf/)
- [RHEL 10 release notes](https://access.redhat.com/articles/red-hat-enterprise-linux-release-dates)

---

**Note**: This migration maintains full backwards compatibility. If you encounter issues on your specific kernel version, please open an issue with your kernel version (`uname -r`) and distribution details.
