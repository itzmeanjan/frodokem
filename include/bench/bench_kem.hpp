#pragma once
#include "kem.hpp"
#include "prng.hpp"
#include <algorithm>
#include <benchmark/benchmark.h>
#include <cassert>
#include <span>
#include <vector>

// Benchmark FrodoKEM and its components
namespace bench_frodo {

namespace utils = frodo_utils;

// Benchmark execution of Frodo key generation algorithm, for some specific
// parameter set.
template<const size_t n,
         const size_t n̄,
         const size_t len_sec,
         const size_t len_SE,
         const size_t len_A,
         const size_t B,
         const size_t D>
inline void
keygen(benchmark::State& state)
{
  constexpr size_t S_LEN = len_sec / 8;
  constexpr size_t SEED_SE_LEN = len_SE / 8;
  constexpr size_t Z_LEN = len_A / 8;
  constexpr size_t PK_LEN = utils::kem_pub_key_len(n, n̄, len_A, D);
  constexpr size_t SK_LEN = utils::kem_sec_key_len(n, n̄, len_sec, len_A, D);

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
    kem::keygen(_s, _seedSE, _z, _pkey, _skey);

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
         const size_t len_sec,
         const size_t len_SE,
         const size_t len_A,
         const size_t len_salt,
         const size_t B,
         const size_t D>
inline void
encaps(benchmark::State& state)
{
  constexpr size_t S_LEN = len_sec / 8;
  constexpr size_t SEED_SE_LEN = len_SE / 8;
  constexpr size_t Z_LEN = len_A / 8;
  constexpr size_t PK_LEN = utils::kem_pub_key_len(n, n̄, len_A, D);
  constexpr size_t SK_LEN = utils::kem_sec_key_len(n, n̄, len_sec, len_A, D);
  constexpr size_t μ_LEN = len_sec / 8;
  constexpr size_t SALT_LEN = len_salt / 8;
  constexpr size_t CT_LEN = utils::kem_cipher_text_len(n, n̄, len_salt, D);
  constexpr size_t SS_LEN = len_sec / 8;

  std::vector<uint8_t> s(S_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> z(Z_LEN, 0);
  std::vector<uint8_t> pkey(PK_LEN, 0);
  std::vector<uint8_t> skey(SK_LEN, 0);
  std::vector<uint8_t> μ(μ_LEN, 0);
  std::vector<uint8_t> salt(SALT_LEN, 0);
  std::vector<uint8_t> cipher(CT_LEN, 0);
  std::vector<uint8_t> ss(SS_LEN, 0);

  std::span<uint8_t, S_LEN> _s{ s };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, Z_LEN> _z{ z };
  std::span<uint8_t, PK_LEN> _pkey{ pkey };
  std::span<uint8_t, SK_LEN> _skey{ skey };
  std::span<uint8_t, μ_LEN> _μ{ μ };
  std::span<uint8_t, μ_LEN> _salt{ salt };
  std::span<uint8_t, CT_LEN> _cipher{ cipher };
  std::span<uint8_t, SS_LEN> _ss{ ss };

  prng::prng_t prng;

  prng.read(_s);
  prng.read(_seedSE);
  prng.read(_z);

  kem::keygen(_s, _seedSE, _z, _pkey, _skey);

  prng.read(_μ);
  prng.read(_salt);

  for (auto _ : state) {
    kem::encaps(_μ, _salt, _pkey, _cipher, _ss);

    benchmark::DoNotOptimize(_μ);
    benchmark::DoNotOptimize(_salt);
    benchmark::DoNotOptimize(_pkey);
    benchmark::DoNotOptimize(_cipher);
    benchmark::DoNotOptimize(_ss);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark execution of Frodo KEM decapsulation algorithm, for some specific
// parameter set.
template<const size_t n,
         const size_t n̄,
         const size_t len_sec,
         const size_t len_SE,
         const size_t len_A,
         const size_t len_salt,
         const size_t B,
         const size_t D>
inline void
decaps(benchmark::State& state)
{
  constexpr size_t S_LEN = len_sec / 8;
  constexpr size_t SEED_SE_LEN = len_SE / 8;
  constexpr size_t Z_LEN = len_A / 8;
  constexpr size_t PK_LEN = utils::kem_pub_key_len(n, n̄, len_A, D);
  constexpr size_t SK_LEN = utils::kem_sec_key_len(n, n̄, len_sec, len_A, D);
  constexpr size_t μ_LEN = len_sec / 8;
  constexpr size_t SALT_LEN = len_salt / 8;
  constexpr size_t CT_LEN = utils::kem_cipher_text_len(n, n̄, len_salt, D);
  constexpr size_t SS_LEN = len_sec / 8;

  std::vector<uint8_t> s(S_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> z(Z_LEN, 0);
  std::vector<uint8_t> pkey(PK_LEN, 0);
  std::vector<uint8_t> skey(SK_LEN, 0);
  std::vector<uint8_t> μ(μ_LEN, 0);
  std::vector<uint8_t> salt(SALT_LEN, 0);
  std::vector<uint8_t> cipher(CT_LEN, 0);
  std::vector<uint8_t> ss0(SS_LEN, 0);
  std::vector<uint8_t> ss1(SS_LEN, 0);

  std::span<uint8_t, S_LEN> _s{ s };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, Z_LEN> _z{ z };
  std::span<uint8_t, PK_LEN> _pkey{ pkey };
  std::span<uint8_t, SK_LEN> _skey{ skey };
  std::span<uint8_t, μ_LEN> _μ{ μ };
  std::span<uint8_t, μ_LEN> _salt{ salt };
  std::span<uint8_t, CT_LEN> _cipher{ cipher };
  std::span<uint8_t, SS_LEN> _ss0{ ss0 };
  std::span<uint8_t, SS_LEN> _ss1{ ss1 };

  prng::prng_t prng;

  prng.read(_s);
  prng.read(_seedSE);
  prng.read(_z);
  prng.read(_μ);
  prng.read(_salt);

  kem::keygen(_s, _seedSE, _z, _pkey, _skey);
  kem::encaps(_μ, _salt, _pkey, _cipher, _ss0);

  for (auto _ : state) {
    kem::decaps(_skey, _cipher, _ss1);

    benchmark::DoNotOptimize(_skey);
    benchmark::DoNotOptimize(_cipher);
    benchmark::DoNotOptimize(_ss1);
    benchmark::ClobberMemory();
  }

  // check if both parties arrived at same shared secret or not !
  assert(std::ranges::equal(_ss0, ss1));

  state.SetItemsProcessed(state.iterations());
}

}
