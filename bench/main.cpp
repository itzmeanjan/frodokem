#include "bench/bench_frodo.hpp"

BENCHMARK(bench_frodo::frodo640_pke_keygen);
BENCHMARK(bench_frodo::frodo640_pke_encrypt);
BENCHMARK(bench_frodo::frodo640_pke_decrypt);

BENCHMARK(bench_frodo::frodo976_pke_keygen);
BENCHMARK(bench_frodo::frodo976_pke_encrypt);
BENCHMARK(bench_frodo::frodo976_pke_decrypt);

BENCHMARK(bench_frodo::frodo1344_pke_keygen);
BENCHMARK(bench_frodo::frodo1344_pke_encrypt);
BENCHMARK(bench_frodo::frodo1344_pke_decrypt);

BENCHMARK_MAIN();
