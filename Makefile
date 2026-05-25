CXX := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -pedantic
LDFLAGS := -lbpf -lelf -lz

# Check if clang is available for eBPF compilation
CLANG := $(shell command -v clang 2>/dev/null)
BPFTOOL := $(shell command -v bpftool 2>/dev/null)

SRC := \
	src/nleash.cpp \
	src/leash_manager.cpp \
	src/cli.cpp \
	src/proc.cpp \
	src/cgroup.cpp \
	src/tc.cpp \
	src/state.cpp \
	src/netutil.cpp

BIN := bin/nleash
HELPER := bin/nleash-helper
BPF_OBJ := bin/tc_cgroup.bpf.o
BPF_SKEL := src/tc_cgroup.skel.h
VMLINUX_H := src/vmlinux.h

# Build eBPF object if clang and bpftool are available, otherwise skip
ifdef CLANG
ifdef BPFTOOL
all: $(VMLINUX_H) $(BPF_SKEL) $(BIN) $(HELPER)
else
all: $(BIN) $(HELPER)
	@echo "Warning: bpftool not found, skipping eBPF CO-RE build"
endif
else
all: $(BIN) $(HELPER)
	@echo "Warning: clang not found, skipping eBPF compilation"
endif

$(VMLINUX_H):
	@mkdir -p src
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(BPF_SKEL)

$(BIN): $(SRC) src/main.cpp $(BPF_SKEL)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -Isrc -o $(BIN) src/main.cpp $(SRC) $(LDFLAGS)

$(HELPER): $(SRC) src/helper_main.cpp $(BPF_SKEL)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -Isrc -o $(HELPER) src/helper_main.cpp $(SRC) $(LDFLAGS)

# Compile eBPF program (requires clang with BPF target support)
$(BPF_OBJ): src/tc_cgroup.bpf.c $(VMLINUX_H)
	@mkdir -p bin
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 -Isrc -I. -c src/tc_cgroup.bpf.c -o $(BPF_OBJ)

test: all
	./tests/nleash-smoke.sh

test-active: all
	NLEASH_ACTIVE=1 ./tests/nleash-smoke.sh

test-net: all
	NLEASH_NETTEST=1 ./tests/nleash-smoke.sh

test-all: all
	NLEASH_ACTIVE=1 NLEASH_NETTEST=1 ./tests/nleash-smoke.sh

clean:
	rm -f $(BIN) $(HELPER) $(BPF_OBJ) $(BPF_SKEL) $(VMLINUX_H)

.PHONY: all clean test test-active test-net test-all
