#include "bench/bench_kem.hpp"

BENCHMARK(bench_frodo::keygen<640, 8, 128, 256, 128, 2, 15>)
  ->Name("frodo640-keygen");
BENCHMARK(bench_frodo::encaps<640, 8, 128, 256, 128, 256, 2, 15>)
  ->Name("frodo640-encaps");
BENCHMARK(bench_frodo::decaps<640, 8, 128, 256, 128, 256, 2, 15>)
  ->Name("frodo640-decaps");

BENCHMARK(bench_frodo::keygen<976, 8, 192, 384, 128, 3, 16>)
  ->Name("frodo976-keygen");
BENCHMARK(bench_frodo::encaps<976, 8, 192, 384, 128, 384, 3, 16>)
  ->Name("frodo976-encaps");
BENCHMARK(bench_frodo::decaps<976, 8, 192, 384, 128, 384, 3, 16>)
  ->Name("frodo976-decaps");

BENCHMARK(bench_frodo::keygen<1344, 8, 256, 512, 128, 4, 16>)
  ->Name("frodo1344-keygen");
BENCHMARK(bench_frodo::encaps<1344, 8, 256, 512, 128, 512, 4, 16>)
  ->Name("frodo1344-encaps");
BENCHMARK(bench_frodo::decaps<1344, 8, 256, 512, 128, 512, 4, 16>)
  ->Name("frodo1344-decaps");

BENCHMARK(bench_frodo::keygen<640, 8, 128, 128, 128, 2, 15>)
  ->Name("efrodo640-keygen");
BENCHMARK(bench_frodo::encaps<640, 8, 128, 128, 128, 0, 2, 15>)
  ->Name("efrodo640-encaps");
BENCHMARK(bench_frodo::decaps<640, 8, 128, 128, 128, 0, 2, 15>)
  ->Name("efrodo640-decaps");

BENCHMARK(bench_frodo::keygen<976, 8, 192, 192, 128, 3, 16>)
  ->Name("efrodo976-keygen");
BENCHMARK(bench_frodo::encaps<976, 8, 192, 192, 128, 0, 3, 16>)
  ->Name("efrodo976-encaps");
BENCHMARK(bench_frodo::decaps<976, 8, 192, 192, 128, 0, 3, 16>)
  ->Name("efrodo976-decaps");

BENCHMARK(bench_frodo::keygen<1344, 8, 256, 256, 128, 4, 16>)
  ->Name("efrodo1344-keygen");
BENCHMARK(bench_frodo::encaps<1344, 8, 256, 256, 128, 0, 4, 16>)
  ->Name("efrodo1344-encaps");
BENCHMARK(bench_frodo::decaps<1344, 8, 256, 256, 128, 0, 4, 16>)
  ->Name("efrodo1344-decaps");

BENCHMARK_MAIN();
