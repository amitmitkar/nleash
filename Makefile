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

clean:
	rm -f $(BIN) $(HELPER)

.PHONY: all clean
