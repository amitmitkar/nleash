CXX := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -pedantic
LDFLAGS :=

SRC := \
	src/nleash.cpp \
	src/cli.cpp \
	src/proc.cpp \
	src/cgroup.cpp \
	src/tc.cpp \
	src/state.cpp \
	src/netutil.cpp

BIN := bin/nleash
HELPER := bin/nleash-helper

all: $(BIN) $(HELPER)

$(BIN): $(SRC) src/main.cpp
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $(BIN) src/main.cpp $(SRC) $(LDFLAGS)

$(HELPER): $(SRC) src/helper_main.cpp
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $(HELPER) src/helper_main.cpp $(SRC) $(LDFLAGS)

test: all
	./tests/nleash-smoke.sh

test-active: all
	NLEASH_ACTIVE=1 ./tests/nleash-smoke.sh

test-net: all
	NLEASH_NETTEST=1 ./tests/nleash-smoke.sh

test-all: all
	NLEASH_ACTIVE=1 NLEASH_NETTEST=1 ./tests/nleash-smoke.sh

clean:
	rm -f $(BIN) $(HELPER)

.PHONY: all clean test test-active test-net test-all
