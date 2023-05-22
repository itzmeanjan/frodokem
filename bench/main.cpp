#include "bench/bench_kem.hpp"

BENCHMARK(bench_frodo::frodo640_kem_keygen);
BENCHMARK(bench_frodo::frodo640_kem_encaps);
BENCHMARK(bench_frodo::frodo640_kem_decaps);

BENCHMARK(bench_frodo::frodo976_kem_keygen);
BENCHMARK(bench_frodo::frodo976_kem_encaps);
BENCHMARK(bench_frodo::frodo976_kem_decaps);

BENCHMARK(bench_frodo::frodo1344_kem_keygen);
BENCHMARK(bench_frodo::frodo1344_kem_encaps);
BENCHMARK(bench_frodo::frodo1344_kem_decaps);

BENCHMARK_MAIN();
