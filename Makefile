CXX = g++
CXX_FLAGS = -std=c++20
WARN_FLAGS = -Wall -Wextra -pedantic
OPT_FLAGS = -O3 -march=native -mtune=native
LINK_FLAGS = -flto
I_FLAGS = -I ./include
DEP_IFLAGS = -I ./sha3/include -I ./subtle/include

SRC_DIR = include
FRODO_SOURCES := $(wildcard $(SRC_DIR)/*.hpp)
BUILD_DIR = build

TEST_DIR = tests
TEST_SOURCES := $(wildcard $(TEST_DIR)/*.cpp)
TEST_OBJECTS := $(addprefix $(BUILD_DIR)/, $(notdir $(patsubst %.cpp,%.o,$(TEST_SOURCES))))
TEST_LINK_FLAGS = -lgtest -lgtest_main
TEST_BINARY = $(BUILD_DIR)/test.out

BENCHMARK_DIR = benchmarks
BENCHMARK_SOURCES := $(wildcard $(BENCHMARK_DIR)/*.cpp)
BENCHMARK_OBJECTS := $(addprefix $(BUILD_DIR)/, $(notdir $(patsubst %.cpp,%.o,$(BENCHMARK_SOURCES))))
BENCHMARK_LINK_FLAGS = -lbenchmark -lbenchmark_main
BENCHMARK_BINARY = $(BUILD_DIR)/bench.out
PERF_LINK_FLAGS = -lbenchmark -lbenchmark_main -lpfm
PERF_BINARY = $(BUILD_DIR)/perf.out

all: test

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/%.o: $(TEST_DIR)/%.cpp $(BUILD_DIR)
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(I_FLAGS) $(DEP_IFLAGS) -c $< -o $@

$(TEST_BINARY): $(TEST_OBJECTS)
	$(CXX) $(OPT_FLAGS) $(LINK_FLAGS) $^ $(TEST_LINK_FLAGS) -o $@

test: $(TEST_BINARY)
	./$<

$(BUILD_DIR)/%.o: $(BENCHMARK_DIR)/%.cpp $(BUILD_DIR)
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(I_FLAGS) $(DEP_IFLAGS) -c $< -o $@

$(BENCHMARK_BINARY): $(BENCHMARK_OBJECTS)
	$(CXX) $(OPT_FLAGS) $(LINK_FLAGS) $^ $(BENCHMARK_LINK_FLAGS) -o $@

benchmark: $(BENCHMARK_BINARY)
	# Must *not* build google-benchmark with libPFM
	./$< --benchmark_time_unit=ms --benchmark_min_warmup_time=1. --benchmark_counters_tabular=true

$(PERF_BINARY): $(BENCHMARK_OBJECTS)
	$(CXX) $(OPT_FLAGS) $(LINK_FLAGS) $^ $(PERF_LINK_FLAGS) -o $@

perf: $(PERF_BINARY)
	# Must build google-benchmark with libPFM, follow https://gist.github.com/itzmeanjan/05dc3e946f635d00c5e0b21aae6203a7
	./$< --benchmark_time_unit=ms --benchmark_min_warmup_time=1. --benchmark_perf_counters=CYCLES --benchmark_counters_tabular=true

.PHONY: format clean

clean:
	rm -rf $(BUILD_DIR)

format: $(FRODO_SOURCES) $(TEST_SOURCES) $(BENCHMARK_SOURCES)
	clang-format -i --style=Mozilla $^
