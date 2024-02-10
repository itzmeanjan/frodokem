#include "bench_helper.hpp"
#include "efrodo1344_kem.hpp"
#include "efrodo640_kem.hpp"
#include "efrodo976_kem.hpp"
#include "frodo1344_kem.hpp"
#include "frodo640_kem.hpp"
#include "frodo976_kem.hpp"
#include "prng.hpp"
#include <benchmark/benchmark.h>
#include <cassert>

namespace utils = frodo_utils;

// Benchmark execution of Frodo key generation algorithm, for some specific
// parameter set.
template<size_t n, size_t n̄, size_t lsec, size_t lSE, size_t lA, size_t B, size_t D>
inline void
keygen(benchmark::State& state)
{
  constexpr size_t S_LEN = lsec / 8;
  constexpr size_t SEED_SE_LEN = lSE / 8;
  constexpr size_t Z_LEN = lA / 8;
  constexpr size_t PK_LEN = utils::kem_pub_key_len(n, n̄, lA, D);
  constexpr size_t SK_LEN = utils::kem_sec_key_len(n, n̄, lsec, lA, D);

  std::vector<uint8_t> s(S_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> z(Z_LEN, 0);
  std::vector<uint8_t> pkey(PK_LEN, 0);
  std::vector<uint8_t> skey(SK_LEN, 0);

  std::span<uint8_t, S_LEN> _s{ s };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, Z_LEN> _z{ z };
  std::span<uint8_t, PK_LEN> _pkey{ pkey };
  std::span<uint8_t, SK_LEN> _skey{ skey };

  prng::prng_t prng;

  prng.read(_s);
  prng.read(_seedSE);
  prng.read(_z);

  for (auto _ : state) {
    kem::keygen<n, n̄, lsec, lSE, lA, B, D>(_s, _seedSE, _z, _pkey, _skey);

    benchmark::DoNotOptimize(_s);
    benchmark::DoNotOptimize(_seedSE);
    benchmark::DoNotOptimize(_z);
    benchmark::DoNotOptimize(_pkey);
    benchmark::DoNotOptimize(_skey);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark execution of Frodo encapsulation algorithm, for some specific
// parameter set.
template<size_t n, size_t n̄, size_t lsec, size_t lSE, size_t lA, size_t lsalt, size_t B, size_t D>
inline void
encaps(benchmark::State& state)
{
  constexpr size_t S_LEN = lsec / 8;
  constexpr size_t SEED_SE_LEN = lSE / 8;
  constexpr size_t Z_LEN = lA / 8;
  constexpr size_t PK_LEN = utils::kem_pub_key_len(n, n̄, lA, D);
  constexpr size_t SK_LEN = utils::kem_sec_key_len(n, n̄, lsec, lA, D);
  constexpr size_t μ_LEN = lsec / 8;
  constexpr size_t SALT_LEN = lsalt / 8;
  constexpr size_t CT_LEN = utils::kem_cipher_text_len(n, n̄, lsalt, D);
  constexpr size_t SS_LEN = lsec / 8;

  std::vector<uint8_t> s(S_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> z(Z_LEN, 0);
  std::vector<uint8_t> pkey(PK_LEN, 0);
  std::vector<uint8_t> skey(SK_LEN, 0);
  std::vector<uint8_t> μ(μ_LEN, 0);
  std::vector<uint8_t> salt(SALT_LEN, 0);
  std::vector<uint8_t> enc(CT_LEN, 0);
  std::vector<uint8_t> ss(SS_LEN, 0);

  std::span<uint8_t, S_LEN> _s{ s };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, Z_LEN> _z{ z };
  std::span<uint8_t, PK_LEN> _pkey{ pkey };
  std::span<uint8_t, SK_LEN> _skey{ skey };
  std::span<uint8_t, μ_LEN> _μ{ μ };
  std::span<uint8_t, SALT_LEN> _salt{ salt };
  std::span<uint8_t, CT_LEN> _enc{ enc };
  std::span<uint8_t, SS_LEN> _ss{ ss };

  prng::prng_t prng;

  prng.read(_s);
  prng.read(_seedSE);
  prng.read(_z);

  kem::keygen<n, n̄, lsec, lSE, lA, B, D>(_s, _seedSE, _z, _pkey, _skey);

  prng.read(_μ);
  prng.read(_salt);

  for (auto _ : state) {
    kem::encaps<n, n̄, lsec, lSE, lA, lsalt, B, D>(_μ, _salt, _pkey, _enc, _ss);

    benchmark::DoNotOptimize(_μ);
    benchmark::DoNotOptimize(_salt);
    benchmark::DoNotOptimize(_pkey);
    benchmark::DoNotOptimize(_enc);
    benchmark::DoNotOptimize(_ss);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark execution of Frodo KEM decapsulation algorithm, for some specific
// parameter set.
template<size_t n, size_t n̄, size_t lsec, size_t lSE, size_t lA, size_t lsalt, size_t B, size_t D>
inline void
decaps(benchmark::State& state)
{
  constexpr size_t S_LEN = lsec / 8;
  constexpr size_t SEED_SE_LEN = lSE / 8;
  constexpr size_t Z_LEN = lA / 8;
  constexpr size_t PK_LEN = utils::kem_pub_key_len(n, n̄, lA, D);
  constexpr size_t SK_LEN = utils::kem_sec_key_len(n, n̄, lsec, lA, D);
  constexpr size_t μ_LEN = lsec / 8;
  constexpr size_t SALT_LEN = lsalt / 8;
  constexpr size_t CT_LEN = utils::kem_cipher_text_len(n, n̄, lsalt, D);
  constexpr size_t SS_LEN = lsec / 8;

  std::vector<uint8_t> s(S_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> z(Z_LEN, 0);
  std::vector<uint8_t> pkey(PK_LEN, 0);
  std::vector<uint8_t> skey(SK_LEN, 0);
  std::vector<uint8_t> μ(μ_LEN, 0);
  std::vector<uint8_t> salt(SALT_LEN, 0);
  std::vector<uint8_t> enc(CT_LEN, 0);
  std::vector<uint8_t> ss0(SS_LEN, 0);
  std::vector<uint8_t> ss1(SS_LEN, 0);

  std::span<uint8_t, S_LEN> _s{ s };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, Z_LEN> _z{ z };
  std::span<uint8_t, PK_LEN> _pkey{ pkey };
  std::span<uint8_t, SK_LEN> _skey{ skey };
  std::span<uint8_t, μ_LEN> _μ{ μ };
  std::span<uint8_t, SALT_LEN> _salt{ salt };
  std::span<uint8_t, CT_LEN> _enc{ enc };
  std::span<uint8_t, SS_LEN> _ss0{ ss0 };
  std::span<uint8_t, SS_LEN> _ss1{ ss1 };

  prng::prng_t prng;

  prng.read(_s);
  prng.read(_seedSE);
  prng.read(_z);
  prng.read(_μ);
  prng.read(_salt);

  kem::keygen<n, n̄, lsec, lSE, lA, B, D>(_s, _seedSE, _z, _pkey, _skey);
  kem::encaps<n, n̄, lsec, lSE, lA, lsalt, B, D>(_μ, _salt, _pkey, _enc, _ss0);

  for (auto _ : state) {
    kem::decaps<n, n̄, lsec, lSE, lA, lsalt, B, D>(_skey, _enc, _ss1);

    benchmark::DoNotOptimize(_skey);
    benchmark::DoNotOptimize(_enc);
    benchmark::DoNotOptimize(_ss1);
    benchmark::ClobberMemory();
  }

  // check if both parties arrived at same shared secret or not !
  assert(std::ranges::equal(_ss0, ss1));

  state.SetItemsProcessed(state.iterations());
}

BENCHMARK(keygen<frodo640_kem::n, frodo640_kem::n̄, frodo640_kem::len_sec, frodo640_kem::len_SE, frodo640_kem::len_A, frodo640_kem::B, frodo640_kem::D>)
  ->Name("frodo640-keygen")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
BENCHMARK(
  encaps<frodo640_kem::n, frodo640_kem::n̄, frodo640_kem::len_sec, frodo640_kem::len_SE, frodo640_kem::len_A, frodo640_kem::len_salt, frodo640_kem::B, frodo640_kem::D>)
  ->Name("frodo640-encaps")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
BENCHMARK(
  decaps<frodo640_kem::n, frodo640_kem::n̄, frodo640_kem::len_sec, frodo640_kem::len_SE, frodo640_kem::len_A, frodo640_kem::len_salt, frodo640_kem::B, frodo640_kem::D>)
  ->Name("frodo640-decaps")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);

BENCHMARK(keygen<frodo976_kem::n, frodo976_kem::n̄, frodo976_kem::len_sec, frodo976_kem::len_SE, frodo976_kem::len_A, frodo976_kem::B, frodo976_kem::D>)
  ->Name("frodo976-keygen")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
BENCHMARK(
  encaps<frodo976_kem::n, frodo976_kem::n̄, frodo976_kem::len_sec, frodo976_kem::len_SE, frodo976_kem::len_A, frodo976_kem::len_salt, frodo976_kem::B, frodo976_kem::D>)
  ->Name("frodo976-encaps")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
BENCHMARK(
  decaps<frodo976_kem::n, frodo976_kem::n̄, frodo976_kem::len_sec, frodo976_kem::len_SE, frodo976_kem::len_A, frodo976_kem::len_salt, frodo976_kem::B, frodo976_kem::D>)
  ->Name("frodo976-decaps")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);

BENCHMARK(keygen<frodo1344_kem::n, frodo1344_kem::n̄, frodo1344_kem::len_sec, frodo1344_kem::len_SE, frodo1344_kem::len_A, frodo1344_kem::B, frodo1344_kem::D>)
  ->Name("frodo1344-keygen")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
BENCHMARK(encaps<frodo1344_kem::n,
                 frodo1344_kem::n̄,
                 frodo1344_kem::len_sec,
                 frodo1344_kem::len_SE,
                 frodo1344_kem::len_A,
                 frodo1344_kem::len_salt,
                 frodo1344_kem::B,
                 frodo1344_kem::D>)
  ->Name("frodo1344-encaps")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
BENCHMARK(decaps<frodo1344_kem::n,
                 frodo1344_kem::n̄,
                 frodo1344_kem::len_sec,
                 frodo1344_kem::len_SE,
                 frodo1344_kem::len_A,
                 frodo1344_kem::len_salt,
                 frodo1344_kem::B,
                 frodo1344_kem::D>)
  ->Name("frodo1344-decaps")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);

BENCHMARK(keygen<efrodo640_kem::n, efrodo640_kem::n̄, efrodo640_kem::len_sec, efrodo640_kem::len_SE, efrodo640_kem::len_A, efrodo640_kem::B, efrodo640_kem::D>)
  ->Name("efrodo640-keygen")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
BENCHMARK(encaps<efrodo640_kem::n,
                 efrodo640_kem::n̄,
                 efrodo640_kem::len_sec,
                 efrodo640_kem::len_SE,
                 efrodo640_kem::len_A,
                 efrodo640_kem::len_salt,
                 efrodo640_kem::B,
                 efrodo640_kem::D>)
  ->Name("efrodo640-encaps")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
BENCHMARK(decaps<efrodo640_kem::n,
                 efrodo640_kem::n̄,
                 efrodo640_kem::len_sec,
                 efrodo640_kem::len_SE,
                 efrodo640_kem::len_A,
                 efrodo640_kem::len_salt,
                 efrodo640_kem::B,
                 efrodo640_kem::D>)
  ->Name("efrodo640-decaps")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);

BENCHMARK(keygen<efrodo976_kem::n, efrodo976_kem::n̄, efrodo976_kem::len_sec, efrodo976_kem::len_SE, efrodo976_kem::len_A, efrodo976_kem::B, efrodo976_kem::D>)
  ->Name("efrodo976-keygen")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
BENCHMARK(encaps<efrodo976_kem::n,
                 efrodo976_kem::n̄,
                 efrodo976_kem::len_sec,
                 efrodo976_kem::len_SE,
                 efrodo976_kem::len_A,
                 efrodo976_kem::len_salt,
                 efrodo976_kem::B,
                 efrodo976_kem::D>)
  ->Name("efrodo976-encaps")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
BENCHMARK(decaps<efrodo976_kem::n,
                 efrodo976_kem::n̄,
                 efrodo976_kem::len_sec,
                 efrodo976_kem::len_SE,
                 efrodo976_kem::len_A,
                 efrodo976_kem::len_salt,
                 efrodo976_kem::B,
                 efrodo976_kem::D>)
  ->Name("efrodo976-decaps")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);

BENCHMARK(keygen<efrodo1344_kem::n, efrodo1344_kem::n̄, efrodo1344_kem::len_sec, efrodo1344_kem::len_SE, efrodo1344_kem::len_A, efrodo1344_kem::B, efrodo1344_kem::D>)
  ->Name("efrodo1344-keygen")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
BENCHMARK(encaps<efrodo1344_kem::n,
                 efrodo1344_kem::n̄,
                 efrodo1344_kem::len_sec,
                 efrodo1344_kem::len_SE,
                 efrodo1344_kem::len_A,
                 efrodo1344_kem::len_salt,
                 efrodo1344_kem::B,
                 efrodo1344_kem::D>)
  ->Name("efrodo1344-encaps")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
BENCHMARK(decaps<efrodo1344_kem::n,
                 efrodo1344_kem::n̄,
                 efrodo1344_kem::len_sec,
                 efrodo1344_kem::len_SE,
                 efrodo1344_kem::len_A,
                 efrodo1344_kem::len_salt,
                 efrodo1344_kem::B,
                 efrodo1344_kem::D>)
  ->Name("efrodo1344-decaps")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
