CXX := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -pedantic
LDFLAGS := -lbpf -lelf -lz

CLANG := $(shell command -v clang 2>/dev/null)
BPFTOOL := $(shell command -v bpftool 2>/dev/null)

SRC := \
	src/nleash.cpp \
	src/leash_manager.cpp \
	src/cli.cpp \
	src/proc.cpp \
	src/cgroup.cpp \
	src/bpf_egress.cpp \
	src/state.cpp

BIN := bin/nleash
HELPER := bin/nleash-helper
BPF_OBJ := bin/leash.bpf.o
BPF_SKEL := src/leash.skel.h
VMLINUX_H := src/vmlinux.h

ifndef CLANG
$(error clang is required for eBPF compilation (install package: clang))
endif
ifndef BPFTOOL
$(error bpftool is required for CO-RE BPF build (install package: bpftool))
endif

all: $(VMLINUX_H) $(BPF_SKEL) $(BIN) $(HELPER)

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

$(BPF_OBJ): src/leash.bpf.c $(VMLINUX_H)
	@mkdir -p bin
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 -Isrc -I. -c src/leash.bpf.c -o $(BPF_OBJ)

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
