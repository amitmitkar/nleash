CXX := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -pedantic
LDFLAGS :=

# Check if clang is available for eBPF compilation
CLANG := $(shell command -v clang 2>/dev/null)

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

# Build eBPF object if clang is available, otherwise skip
ifdef CLANG
all: $(BIN) $(HELPER) $(BPF_OBJ)
else
all: $(BIN) $(HELPER)
	@echo "Warning: clang not found, skipping eBPF compilation (required for kernel 6.0+)"
endif

$(BIN): $(SRC) src/main.cpp
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $(BIN) src/main.cpp $(SRC) $(LDFLAGS)

$(HELPER): $(SRC) src/helper_main.cpp
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $(HELPER) src/helper_main.cpp $(SRC) $(LDFLAGS)

# Compile eBPF program (requires clang with BPF target support)
$(BPF_OBJ): src/tc_cgroup.bpf.c
	@mkdir -p bin
ifdef CLANG
	$(CLANG) -O2 -g -target bpf -c src/tc_cgroup.bpf.c -o $(BPF_OBJ)
else
	@echo "Error: clang not found, cannot compile eBPF program"
	@exit 1
endif

test: all
	./tests/nleash-smoke.sh

test-active: all
	NLEASH_ACTIVE=1 ./tests/nleash-smoke.sh

test-net: all
	NLEASH_NETTEST=1 ./tests/nleash-smoke.sh

test-all: all
	NLEASH_ACTIVE=1 NLEASH_NETTEST=1 ./tests/nleash-smoke.sh

clean:
	rm -f $(BIN) $(HELPER) $(BPF_OBJ)

.PHONY: all clean test test-active test-net test-all
