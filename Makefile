CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -pedantic
OPTFLAGS = -O3 -march=native -mtune=native
IFLAGS = -I ./include
DEPFLAGS = -I ./sha3/include -I ./subtle/include

all: testing

test/a.out: test/main.cpp include/*.hpp include/test/*.hpp sha3/include/*.hpp subtle/include/*.hpp
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(IFLAGS) $(DEPFLAGS) $< -o $@

testing: test/a.out
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
