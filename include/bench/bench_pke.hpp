#pragma once
#include "frodo1344_pke.hpp"
#include "frodo640_pke.hpp"
#include "frodo976_pke.hpp"
#include <benchmark/benchmark.h>

// Benchmark FrodoKEM and its components
namespace bench_frodo {

// Benchmark execution of Frodo640 PKE's key generation algorithm.
inline void
frodo640_pke_keygen(benchmark::State& state)
{
  constexpr size_t SLEN0 = 16;
  constexpr size_t SLEN1 = 16;

  auto seedA = static_cast<uint8_t*>(std::malloc(SLEN0));
  auto seedSE = static_cast<uint8_t*>(std::malloc(SLEN1));
  auto pkey = static_cast<uint8_t*>(std::malloc(frodo640_pke::PUB_KEY_LEN));
  auto skey = static_cast<uint8_t*>(std::malloc(frodo640_pke::SEC_KEY_LEN));

  prng::prng_t prng;

  prng.read(seedA, SLEN0);
  prng.read(seedSE, SLEN1);

  for (auto _ : state) {
    frodo640_pke::keygen(seedA, seedSE, pkey, skey);

    benchmark::DoNotOptimize(seedA);
    benchmark::DoNotOptimize(seedSE);
    benchmark::DoNotOptimize(pkey);
    benchmark::DoNotOptimize(skey);
    benchmark::ClobberMemory();
  }

  std::free(seedA);
  std::free(seedSE);
  std::free(pkey);
  std::free(skey);
}

// Benchmark execution of Frodo976 PKE's key generation algorithm.
inline void
frodo976_pke_keygen(benchmark::State& state)
{
  constexpr size_t SLEN0 = 16;
  constexpr size_t SLEN1 = 24;

  auto seedA = static_cast<uint8_t*>(std::malloc(SLEN0));
  auto seedSE = static_cast<uint8_t*>(std::malloc(SLEN1));
  auto pkey = static_cast<uint8_t*>(std::malloc(frodo976_pke::PUB_KEY_LEN));
  auto skey = static_cast<uint8_t*>(std::malloc(frodo976_pke::SEC_KEY_LEN));

  prng::prng_t prng;

  prng.read(seedA, SLEN0);
  prng.read(seedSE, SLEN1);

  for (auto _ : state) {
    frodo976_pke::keygen(seedA, seedSE, pkey, skey);

    benchmark::DoNotOptimize(seedA);
    benchmark::DoNotOptimize(seedSE);
    benchmark::DoNotOptimize(pkey);
    benchmark::DoNotOptimize(skey);
    benchmark::ClobberMemory();
  }

  std::free(seedA);
  std::free(seedSE);
  std::free(pkey);
  std::free(skey);
}

// Benchmark execution of Frodo1344 PKE's key generation algorithm.
inline void
frodo1344_pke_keygen(benchmark::State& state)
{
  constexpr size_t SLEN0 = 16;
  constexpr size_t SLEN1 = 32;

  auto seedA = static_cast<uint8_t*>(std::malloc(SLEN0));
  auto seedSE = static_cast<uint8_t*>(std::malloc(SLEN1));
  auto pkey = static_cast<uint8_t*>(std::malloc(frodo1344_pke::PUB_KEY_LEN));
  auto skey = static_cast<uint8_t*>(std::malloc(frodo1344_pke::SEC_KEY_LEN));

  prng::prng_t prng;

  prng.read(seedA, SLEN0);
  prng.read(seedSE, SLEN1);

  for (auto _ : state) {
    frodo1344_pke::keygen(seedA, seedSE, pkey, skey);

    benchmark::DoNotOptimize(seedA);
    benchmark::DoNotOptimize(seedSE);
    benchmark::DoNotOptimize(pkey);
    benchmark::DoNotOptimize(skey);
    benchmark::ClobberMemory();
  }

  std::free(seedA);
  std::free(seedSE);
  std::free(pkey);
  std::free(skey);
}

}
