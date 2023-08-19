CXX = g++
CXX_FLAGS = -std=c++20
WARN_FLAGS = -Wall -Wextra -pedantic
OPT_FLAGS = -O3 -march=native -mtune=native
LINK_FLAGS = -flto
I_FLAGS = -I ./include
DEP_IFLAGS = -I ./sha3/include -I ./subtle/include

BUILD_DIR = build

TEST_DIR = tests
TEST_SOURCES := $(wildcard $(TEST_DIR)/*.cpp)
TEST_OBJECTS := $(addprefix $(BUILD_DIR)/, $(notdir $(patsubst %.cpp,%.o,$(TEST_SOURCES))))

TEST_LINK_FLAGS = -lgtest -lgtest_main
TEST_BINARY = $(BUILD_DIR)/test.out

all: $(BUILD_DIR) test

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/%.o: $(TEST_DIR)/%.cpp
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(I_FLAGS) $(DEP_IFLAGS) -c $< -o $@

$(TEST_BINARY): $(TEST_OBJECTS)
	$(CXX) $(OPT_FLAGS) $(LINK_FLAGS) $^ $(TEST_LINK_FLAGS) -o $@

test: $(TEST_BINARY)
	./$<

bench/a.out: bench/main.cpp include/*.hpp include/bench/*.hpp sha3/include/*.hpp subtle/include/*.hpp
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(IFLAGS) $(DEPFLAGS) $< -lbenchmark -o $@

benchmark: bench/a.out
	# Don't forget to put all CPU cores on performance mode before running benchmarks,
	# follow https://github.com/google/benchmark/blob/2dd015df/docs/reducing_variance.md
	./$< --benchmark_time_unit=ms --benchmark_counters_tabular=true

clean:
	find . -name '*.out' -o -name '*.o' -o -name '*.so' -o -name '*.gch' | xargs rm -rf

format:
	find . -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i --style=Mozilla
