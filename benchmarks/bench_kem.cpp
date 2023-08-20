#include "kem.hpp"
#include "prng.hpp"
#include <algorithm>
#include <benchmark/benchmark.h>
#include <cassert>
#include <span>
#include <vector>

namespace utils = frodo_utils;

// Benchmark execution of Frodo key generation algorithm, for some specific
// parameter set.
template<const size_t n,
         const size_t n̄,
         const size_t lsec,
         const size_t lSE,
         const size_t lA,
         const size_t B,
         const size_t D>
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
template<const size_t n,
         const size_t n̄,
         const size_t lsec,
         const size_t lSE,
         const size_t lA,
         const size_t lsalt,
         const size_t B,
         const size_t D>
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
template<const size_t n,
         const size_t n̄,
         const size_t lsec,
         const size_t lSE,
         const size_t lA,
         const size_t lsalt,
         const size_t B,
         const size_t D>
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

BENCHMARK(keygen<640, 8, 128, 256, 128, 2, 15>)->Name("frodo640-keygen");
BENCHMARK(encaps<640, 8, 128, 256, 128, 256, 2, 15>)->Name("frodo640-encaps");
BENCHMARK(decaps<640, 8, 128, 256, 128, 256, 2, 15>)->Name("frodo640-decaps");

BENCHMARK(keygen<976, 8, 192, 384, 128, 3, 16>)->Name("frodo976-keygen");
BENCHMARK(encaps<976, 8, 192, 384, 128, 384, 3, 16>)->Name("frodo976-encaps");
BENCHMARK(decaps<976, 8, 192, 384, 128, 384, 3, 16>)->Name("frodo976-decaps");

BENCHMARK(keygen<1344, 8, 256, 512, 128, 4, 16>)->Name("frodo1344-keygen");
BENCHMARK(encaps<1344, 8, 256, 512, 128, 512, 4, 16>)->Name("frodo1344-encaps");
BENCHMARK(decaps<1344, 8, 256, 512, 128, 512, 4, 16>)->Name("frodo1344-decaps");

BENCHMARK(keygen<640, 8, 128, 128, 128, 2, 15>)->Name("efrodo640-keygen");
BENCHMARK(encaps<640, 8, 128, 128, 128, 0, 2, 15>)->Name("efrodo640-encaps");
BENCHMARK(decaps<640, 8, 128, 128, 128, 0, 2, 15>)->Name("efrodo640-decaps");

BENCHMARK(keygen<976, 8, 192, 192, 128, 3, 16>)->Name("efrodo976-keygen");
BENCHMARK(encaps<976, 8, 192, 192, 128, 0, 3, 16>)->Name("efrodo976-encaps");
BENCHMARK(decaps<976, 8, 192, 192, 128, 0, 3, 16>)->Name("efrodo976-decaps");

BENCHMARK(keygen<1344, 8, 256, 256, 128, 4, 16>)->Name("efrodo1344-keygen");
BENCHMARK(encaps<1344, 8, 256, 256, 128, 0, 4, 16>)->Name("efrodo1344-encaps");
BENCHMARK(decaps<1344, 8, 256, 256, 128, 0, 4, 16>)->Name("efrodo1344-decaps");
