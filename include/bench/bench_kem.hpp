#pragma once
#include "frodo1344_kem.hpp"
#include "frodo640_kem.hpp"
#include "frodo976_kem.hpp"
#include "prng.hpp"
#include <algorithm>
#include <benchmark/benchmark.h>
#include <cassert>
#include <span>
#include <vector>

// Benchmark FrodoKEM and its components
namespace bench_frodo {

// Benchmark execution of Frodo-640 KEM key generation algorithm.
inline void
frodo640_kem_keygen(benchmark::State& state)
{
  constexpr size_t S_LEN = 16;
  constexpr size_t SEED_SE_LEN = 16;
  constexpr size_t Z_LEN = 16;

  std::vector<uint8_t> s(S_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> z(Z_LEN, 0);
  std::vector<uint8_t> pkey(frodo640_kem::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo640_kem::SEC_KEY_LEN, 0);

  std::span<uint8_t, S_LEN> _s{ s };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, Z_LEN> _z{ z };
  std::span<uint8_t, frodo640_kem::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo640_kem::SEC_KEY_LEN> _skey{ skey };

  prng::prng_t prng;

  prng.read(_s.data(), _s.size());
  prng.read(_seedSE.data(), _seedSE.size());
  prng.read(_z.data(), _z.size());

  for (auto _ : state) {
    frodo640_kem::keygen(_s, _seedSE, _z, _pkey, _skey);

    benchmark::DoNotOptimize(_s);
    benchmark::DoNotOptimize(_seedSE);
    benchmark::DoNotOptimize(_z);
    benchmark::DoNotOptimize(_pkey);
    benchmark::DoNotOptimize(_skey);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark execution of Frodo-640 KEM encapsulation algorithm.
inline void
frodo640_kem_encaps(benchmark::State& state)
{
  constexpr size_t S_LEN = 16;
  constexpr size_t SEED_SE_LEN = 16;
  constexpr size_t Z_LEN = 16;
  constexpr size_t μ_LEN = 16;
  constexpr size_t SS_LEN = 16;

  std::vector<uint8_t> s(S_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> z(Z_LEN, 0);
  std::vector<uint8_t> pkey(frodo640_kem::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo640_kem::SEC_KEY_LEN, 0);
  std::vector<uint8_t> μ(μ_LEN, 0);
  std::vector<uint8_t> cipher(frodo640_kem::CIPHER_LEN, 0);
  std::vector<uint8_t> ss(SS_LEN, 0);

  std::span<uint8_t, S_LEN> _s{ s };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, Z_LEN> _z{ z };
  std::span<uint8_t, frodo640_kem::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo640_kem::SEC_KEY_LEN> _skey{ skey };
  std::span<uint8_t, μ_LEN> _μ{ μ };
  std::span<uint8_t, frodo640_kem::CIPHER_LEN> _cipher{ cipher };
  std::span<uint8_t, SS_LEN> _ss{ ss };

  prng::prng_t prng;

  prng.read(_s.data(), _s.size());
  prng.read(_seedSE.data(), _seedSE.size());
  prng.read(_z.data(), _z.size());

  frodo640_kem::keygen(_s, _seedSE, _z, _pkey, _skey);

  prng.read(_μ.data(), _μ.size());

  for (auto _ : state) {
    frodo640_kem::encaps(_μ, _pkey, _cipher, _ss);

    benchmark::DoNotOptimize(_μ);
    benchmark::DoNotOptimize(_pkey);
    benchmark::DoNotOptimize(_cipher);
    benchmark::DoNotOptimize(_ss);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark execution of Frodo-640 KEM decapsulation algorithm.
inline void
frodo640_kem_decaps(benchmark::State& state)
{
  constexpr size_t S_LEN = 16;
  constexpr size_t SEED_SE_LEN = 16;
  constexpr size_t Z_LEN = 16;
  constexpr size_t μ_LEN = 16;
  constexpr size_t SS_LEN = 16;

  std::vector<uint8_t> s(S_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> z(Z_LEN, 0);
  std::vector<uint8_t> pkey(frodo640_kem::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo640_kem::SEC_KEY_LEN, 0);
  std::vector<uint8_t> μ(μ_LEN, 0);
  std::vector<uint8_t> cipher(frodo640_kem::CIPHER_LEN, 0);
  std::vector<uint8_t> ss0(SS_LEN, 0);
  std::vector<uint8_t> ss1(SS_LEN, 0);

  std::span<uint8_t, S_LEN> _s{ s };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, Z_LEN> _z{ z };
  std::span<uint8_t, frodo640_kem::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo640_kem::SEC_KEY_LEN> _skey{ skey };
  std::span<uint8_t, μ_LEN> _μ{ μ };
  std::span<uint8_t, frodo640_kem::CIPHER_LEN> _cipher{ cipher };
  std::span<uint8_t, SS_LEN> _ss0{ ss0 };
  std::span<uint8_t, SS_LEN> _ss1{ ss1 };

  prng::prng_t prng;

  prng.read(_s.data(), _s.size());
  prng.read(_seedSE.data(), _seedSE.size());
  prng.read(_z.data(), _z.size());
  prng.read(_μ.data(), _μ.size());

  frodo640_kem::keygen(_s, _seedSE, _z, _pkey, _skey);
  frodo640_kem::encaps(_μ, _pkey, _cipher, _ss0);

  for (auto _ : state) {
    frodo640_kem::decaps(_skey, _cipher, _ss1);

    benchmark::DoNotOptimize(_skey);
    benchmark::DoNotOptimize(_cipher);
    benchmark::DoNotOptimize(_ss1);
    benchmark::ClobberMemory();
  }

  // check if both parties arrived at same shared secret or not !
  assert(std::ranges::equal(_ss0, ss1));

  state.SetItemsProcessed(state.iterations());
}

// Benchmark execution of Frodo-976 KEM key generation algorithm.
inline void
frodo976_kem_keygen(benchmark::State& state)
{
  constexpr size_t S_LEN = 24;
  constexpr size_t SEED_SE_LEN = 24;
  constexpr size_t Z_LEN = 16;

  std::vector<uint8_t> s(S_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> z(Z_LEN, 0);
  std::vector<uint8_t> pkey(frodo976_kem::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo976_kem::SEC_KEY_LEN, 0);

  std::span<uint8_t, S_LEN> _s{ s };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, Z_LEN> _z{ z };
  std::span<uint8_t, frodo976_kem::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo976_kem::SEC_KEY_LEN> _skey{ skey };

  prng::prng_t prng;

  prng.read(_s.data(), _s.size());
  prng.read(_seedSE.data(), _seedSE.size());
  prng.read(_z.data(), _z.size());

  for (auto _ : state) {
    frodo976_kem::keygen(_s, _seedSE, _z, _pkey, _skey);

    benchmark::DoNotOptimize(_s);
    benchmark::DoNotOptimize(_seedSE);
    benchmark::DoNotOptimize(_z);
    benchmark::DoNotOptimize(_pkey);
    benchmark::DoNotOptimize(_skey);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark execution of Frodo-976 KEM encapsulation algorithm.
inline void
frodo976_kem_encaps(benchmark::State& state)
{
  constexpr size_t S_LEN = 24;
  constexpr size_t SEED_SE_LEN = 24;
  constexpr size_t Z_LEN = 16;
  constexpr size_t μ_LEN = 24;
  constexpr size_t SS_LEN = 24;

  std::vector<uint8_t> s(S_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> z(Z_LEN, 0);
  std::vector<uint8_t> pkey(frodo976_kem::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo976_kem::SEC_KEY_LEN, 0);
  std::vector<uint8_t> μ(μ_LEN, 0);
  std::vector<uint8_t> cipher(frodo976_kem::CIPHER_LEN, 0);
  std::vector<uint8_t> ss(SS_LEN, 0);

  std::span<uint8_t, S_LEN> _s{ s };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, Z_LEN> _z{ z };
  std::span<uint8_t, frodo976_kem::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo976_kem::SEC_KEY_LEN> _skey{ skey };
  std::span<uint8_t, μ_LEN> _μ{ μ };
  std::span<uint8_t, frodo976_kem::CIPHER_LEN> _cipher{ cipher };
  std::span<uint8_t, SS_LEN> _ss{ ss };

  prng::prng_t prng;

  prng.read(_s.data(), _s.size());
  prng.read(_seedSE.data(), _seedSE.size());
  prng.read(_z.data(), _z.size());

  frodo976_kem::keygen(_s, _seedSE, _z, _pkey, _skey);

  prng.read(_μ.data(), _μ.size());

  for (auto _ : state) {
    frodo976_kem::encaps(_μ, _pkey, _cipher, _ss);

    benchmark::DoNotOptimize(_μ);
    benchmark::DoNotOptimize(_pkey);
    benchmark::DoNotOptimize(_cipher);
    benchmark::DoNotOptimize(_ss);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark execution of Frodo-976 KEM decapsulation algorithm.
inline void
frodo976_kem_decaps(benchmark::State& state)
{
  constexpr size_t S_LEN = 24;
  constexpr size_t SEED_SE_LEN = 24;
  constexpr size_t Z_LEN = 16;
  constexpr size_t μ_LEN = 24;
  constexpr size_t SS_LEN = 24;

  std::vector<uint8_t> s(S_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> z(Z_LEN, 0);
  std::vector<uint8_t> pkey(frodo976_kem::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo976_kem::SEC_KEY_LEN, 0);
  std::vector<uint8_t> μ(μ_LEN, 0);
  std::vector<uint8_t> cipher(frodo976_kem::CIPHER_LEN, 0);
  std::vector<uint8_t> ss0(SS_LEN, 0);
  std::vector<uint8_t> ss1(SS_LEN, 0);

  std::span<uint8_t, S_LEN> _s{ s };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, Z_LEN> _z{ z };
  std::span<uint8_t, frodo976_kem::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo976_kem::SEC_KEY_LEN> _skey{ skey };
  std::span<uint8_t, μ_LEN> _μ{ μ };
  std::span<uint8_t, frodo976_kem::CIPHER_LEN> _cipher{ cipher };
  std::span<uint8_t, SS_LEN> _ss0{ ss0 };
  std::span<uint8_t, SS_LEN> _ss1{ ss1 };

  prng::prng_t prng;

  prng.read(_s.data(), _s.size());
  prng.read(_seedSE.data(), _seedSE.size());
  prng.read(_z.data(), _z.size());
  prng.read(_μ.data(), _μ.size());

  frodo976_kem::keygen(_s, _seedSE, _z, _pkey, _skey);
  frodo976_kem::encaps(_μ, _pkey, _cipher, _ss0);

  for (auto _ : state) {
    frodo976_kem::decaps(_skey, _cipher, _ss1);

    benchmark::DoNotOptimize(_skey);
    benchmark::DoNotOptimize(_cipher);
    benchmark::DoNotOptimize(_ss1);
    benchmark::ClobberMemory();
  }

  // check if both parties arrived at same shared secret or not !
  assert(std::ranges::equal(_ss0, ss1));

  state.SetItemsProcessed(state.iterations());
}

// Benchmark execution of Frodo-1344 KEM key generation algorithm.
inline void
frodo1344_kem_keygen(benchmark::State& state)
{
  constexpr size_t S_LEN = 32;
  constexpr size_t SEED_SE_LEN = 32;
  constexpr size_t Z_LEN = 16;

  std::vector<uint8_t> s(S_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> z(Z_LEN, 0);
  std::vector<uint8_t> pkey(frodo1344_kem::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo1344_kem::SEC_KEY_LEN, 0);

  std::span<uint8_t, S_LEN> _s{ s };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, Z_LEN> _z{ z };
  std::span<uint8_t, frodo1344_kem::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo1344_kem::SEC_KEY_LEN> _skey{ skey };

  prng::prng_t prng;

  prng.read(_s.data(), _s.size());
  prng.read(_seedSE.data(), _seedSE.size());
  prng.read(_z.data(), _z.size());

  for (auto _ : state) {
    frodo1344_kem::keygen(_s, _seedSE, _z, _pkey, _skey);

    benchmark::DoNotOptimize(_s);
    benchmark::DoNotOptimize(_seedSE);
    benchmark::DoNotOptimize(_z);
    benchmark::DoNotOptimize(_pkey);
    benchmark::DoNotOptimize(_skey);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark execution of Frodo-1344 KEM encapsulation algorithm.
inline void
frodo1344_kem_encaps(benchmark::State& state)
{
  constexpr size_t S_LEN = 32;
  constexpr size_t SEED_SE_LEN = 32;
  constexpr size_t Z_LEN = 16;
  constexpr size_t μ_LEN = 32;
  constexpr size_t SS_LEN = 32;

  std::vector<uint8_t> s(S_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> z(Z_LEN, 0);
  std::vector<uint8_t> pkey(frodo1344_kem::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo1344_kem::SEC_KEY_LEN, 0);
  std::vector<uint8_t> μ(μ_LEN, 0);
  std::vector<uint8_t> cipher(frodo1344_kem::CIPHER_LEN, 0);
  std::vector<uint8_t> ss(SS_LEN, 0);

  std::span<uint8_t, S_LEN> _s{ s };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, Z_LEN> _z{ z };
  std::span<uint8_t, frodo1344_kem::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo1344_kem::SEC_KEY_LEN> _skey{ skey };
  std::span<uint8_t, μ_LEN> _μ{ μ };
  std::span<uint8_t, frodo1344_kem::CIPHER_LEN> _cipher{ cipher };
  std::span<uint8_t, SS_LEN> _ss{ ss };

  prng::prng_t prng;

  prng.read(_s.data(), _s.size());
  prng.read(_seedSE.data(), _seedSE.size());
  prng.read(_z.data(), _z.size());

  frodo1344_kem::keygen(_s, _seedSE, _z, _pkey, _skey);

  prng.read(_μ.data(), _μ.size());

  for (auto _ : state) {
    frodo1344_kem::encaps(_μ, _pkey, _cipher, _ss);

    benchmark::DoNotOptimize(_μ);
    benchmark::DoNotOptimize(_pkey);
    benchmark::DoNotOptimize(_cipher);
    benchmark::DoNotOptimize(_ss);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark execution of Frodo-1344 KEM decapsulation algorithm.
inline void
frodo1344_kem_decaps(benchmark::State& state)
{
  constexpr size_t S_LEN = 32;
  constexpr size_t SEED_SE_LEN = 32;
  constexpr size_t Z_LEN = 16;
  constexpr size_t μ_LEN = 32;
  constexpr size_t SS_LEN = 32;

  std::vector<uint8_t> s(S_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> z(Z_LEN, 0);
  std::vector<uint8_t> pkey(frodo1344_kem::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo1344_kem::SEC_KEY_LEN, 0);
  std::vector<uint8_t> μ(μ_LEN, 0);
  std::vector<uint8_t> cipher(frodo1344_kem::CIPHER_LEN, 0);
  std::vector<uint8_t> ss0(SS_LEN, 0);
  std::vector<uint8_t> ss1(SS_LEN, 0);

  std::span<uint8_t, S_LEN> _s{ s };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, Z_LEN> _z{ z };
  std::span<uint8_t, frodo1344_kem::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo1344_kem::SEC_KEY_LEN> _skey{ skey };
  std::span<uint8_t, μ_LEN> _μ{ μ };
  std::span<uint8_t, frodo1344_kem::CIPHER_LEN> _cipher{ cipher };
  std::span<uint8_t, SS_LEN> _ss0{ ss0 };
  std::span<uint8_t, SS_LEN> _ss1{ ss1 };

  prng::prng_t prng;

  prng.read(_s.data(), _s.size());
  prng.read(_seedSE.data(), _seedSE.size());
  prng.read(_z.data(), _z.size());
  prng.read(_μ.data(), _μ.size());

  frodo1344_kem::keygen(_s, _seedSE, _z, _pkey, _skey);
  frodo1344_kem::encaps(_μ, _pkey, _cipher, _ss0);

  for (auto _ : state) {
    frodo1344_kem::decaps(_skey, _cipher, _ss1);

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