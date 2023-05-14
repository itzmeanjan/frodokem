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
  constexpr size_t SEED_A_LEN = 16;
  constexpr size_t SEED_SE_LEN = 16;

  std::vector<uint8_t> seedA(SEED_A_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> pkey(frodo640_pke::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo640_pke::SEC_KEY_LEN, 0);

  std::span<uint8_t, SEED_A_LEN> _seedA{ seedA };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, frodo640_pke::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo640_pke::SEC_KEY_LEN> _skey{ skey };

  prng::prng_t prng;

  prng.read(_seedA.data(), SEED_A_LEN);
  prng.read(_seedSE.data(), SEED_SE_LEN);

  for (auto _ : state) {
    frodo640_pke::keygen(_seedA, _seedSE, _pkey, _skey);

    benchmark::DoNotOptimize(_seedA);
    benchmark::DoNotOptimize(_seedSE);
    benchmark::DoNotOptimize(_pkey);
    benchmark::DoNotOptimize(_skey);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark execution of Frodo640 PKE's encryption algorithm.
inline void
frodo640_pke_encrypt(benchmark::State& state)
{
  constexpr size_t SEED_A_LEN = 16;
  constexpr size_t SEED_SE_LEN = 16;
  constexpr size_t MLEN = 16;

  std::vector<uint8_t> seedA(SEED_A_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> pkey(frodo640_pke::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo640_pke::SEC_KEY_LEN, 0);
  std::vector<uint8_t> msg(MLEN, 0);
  std::vector<uint8_t> enc(frodo640_pke::CIPHER_LEN, 0);

  std::span<uint8_t, SEED_A_LEN> _seedA{ seedA };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, frodo640_pke::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo640_pke::SEC_KEY_LEN> _skey{ skey };
  std::span<uint8_t, MLEN> _msg{ msg };
  std::span<uint8_t, frodo640_pke::CIPHER_LEN> _enc{ enc };

  prng::prng_t prng;

  prng.read(_seedA.data(), SEED_A_LEN);
  prng.read(_seedSE.data(), SEED_SE_LEN);
  prng.read(_msg.data(), MLEN);

  frodo640_pke::keygen(_seedA, _seedSE, _pkey, _skey);

  for (auto _ : state) {
    frodo640_pke::encrypt(_seedSE, _pkey, _msg, _enc);

    benchmark::DoNotOptimize(_seedSE);
    benchmark::DoNotOptimize(_pkey);
    benchmark::DoNotOptimize(_msg);
    benchmark::DoNotOptimize(_enc);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark execution of Frodo640 PKE's decryption algorithm.
inline void
frodo640_pke_decrypt(benchmark::State& state)
{
  constexpr size_t SEED_A_LEN = 16;
  constexpr size_t SEED_SE_LEN = 16;
  constexpr size_t MLEN = 16;

  std::vector<uint8_t> seedA(SEED_A_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> pkey(frodo640_pke::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo640_pke::SEC_KEY_LEN, 0);
  std::vector<uint8_t> msg(MLEN, 0);
  std::vector<uint8_t> enc(frodo640_pke::CIPHER_LEN, 0);
  std::vector<uint8_t> dec(MLEN, 0);

  std::span<uint8_t, SEED_A_LEN> _seedA{ seedA };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, frodo640_pke::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo640_pke::SEC_KEY_LEN> _skey{ skey };
  std::span<uint8_t, MLEN> _msg{ msg };
  std::span<uint8_t, frodo640_pke::CIPHER_LEN> _enc{ enc };
  std::span<uint8_t, MLEN> _dec{ dec };

  prng::prng_t prng;

  prng.read(_seedA.data(), SEED_A_LEN);
  prng.read(_seedSE.data(), SEED_SE_LEN);
  prng.read(_msg.data(), MLEN);

  frodo640_pke::keygen(_seedA, _seedSE, _pkey, _skey);
  frodo640_pke::encrypt(_seedSE, _pkey, _msg, _enc);

  for (auto _ : state) {
    frodo640_pke::decrypt(_skey, _enc, _dec);

    benchmark::DoNotOptimize(_skey);
    benchmark::DoNotOptimize(_enc);
    benchmark::DoNotOptimize(_dec);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark execution of Frodo976 PKE's key generation algorithm.
inline void
frodo976_pke_keygen(benchmark::State& state)
{
  constexpr size_t SEED_A_LEN = 16;
  constexpr size_t SEED_SE_LEN = 24;

  std::vector<uint8_t> seedA(SEED_A_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> pkey(frodo976_pke::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo976_pke::SEC_KEY_LEN, 0);

  std::span<uint8_t, SEED_A_LEN> _seedA{ seedA };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, frodo976_pke::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo976_pke::SEC_KEY_LEN> _skey{ skey };

  prng::prng_t prng;

  prng.read(_seedA.data(), SEED_A_LEN);
  prng.read(_seedSE.data(), SEED_SE_LEN);

  for (auto _ : state) {
    frodo976_pke::keygen(_seedA, _seedSE, _pkey, _skey);

    benchmark::DoNotOptimize(_seedA);
    benchmark::DoNotOptimize(_seedSE);
    benchmark::DoNotOptimize(_pkey);
    benchmark::DoNotOptimize(_skey);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark execution of Frodo976 PKE's encryption algorithm.
inline void
frodo976_pke_encrypt(benchmark::State& state)
{
  constexpr size_t SEED_A_LEN = 16;
  constexpr size_t SEED_SE_LEN = 24;
  constexpr size_t MLEN = 24;

  std::vector<uint8_t> seedA(SEED_A_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> pkey(frodo976_pke::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo976_pke::SEC_KEY_LEN, 0);
  std::vector<uint8_t> msg(MLEN, 0);
  std::vector<uint8_t> enc(frodo976_pke::CIPHER_LEN, 0);

  std::span<uint8_t, SEED_A_LEN> _seedA{ seedA };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, frodo976_pke::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo976_pke::SEC_KEY_LEN> _skey{ skey };
  std::span<uint8_t, MLEN> _msg{ msg };
  std::span<uint8_t, frodo976_pke::CIPHER_LEN> _enc{ enc };

  prng::prng_t prng;

  prng.read(_seedA.data(), SEED_A_LEN);
  prng.read(_seedSE.data(), SEED_SE_LEN);
  prng.read(_msg.data(), MLEN);

  frodo976_pke::keygen(_seedA, _seedSE, _pkey, _skey);

  for (auto _ : state) {
    frodo976_pke::encrypt(_seedSE, _pkey, _msg, _enc);

    benchmark::DoNotOptimize(_seedSE);
    benchmark::DoNotOptimize(_pkey);
    benchmark::DoNotOptimize(_msg);
    benchmark::DoNotOptimize(_enc);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark execution of Frodo976 PKE's decryption algorithm.
inline void
frodo976_pke_decrypt(benchmark::State& state)
{
  constexpr size_t SEED_A_LEN = 16;
  constexpr size_t SEED_SE_LEN = 24;
  constexpr size_t MLEN = 24;

  std::vector<uint8_t> seedA(SEED_A_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> pkey(frodo976_pke::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo976_pke::SEC_KEY_LEN, 0);
  std::vector<uint8_t> msg(MLEN, 0);
  std::vector<uint8_t> enc(frodo976_pke::CIPHER_LEN, 0);
  std::vector<uint8_t> dec(MLEN, 0);

  std::span<uint8_t, SEED_A_LEN> _seedA{ seedA };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, frodo976_pke::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo976_pke::SEC_KEY_LEN> _skey{ skey };
  std::span<uint8_t, MLEN> _msg{ msg };
  std::span<uint8_t, frodo976_pke::CIPHER_LEN> _enc{ enc };
  std::span<uint8_t, MLEN> _dec{ dec };

  prng::prng_t prng;

  prng.read(_seedA.data(), SEED_A_LEN);
  prng.read(_seedSE.data(), SEED_SE_LEN);
  prng.read(_msg.data(), MLEN);

  frodo976_pke::keygen(_seedA, _seedSE, _pkey, _skey);
  frodo976_pke::encrypt(_seedSE, _pkey, _msg, _enc);

  for (auto _ : state) {
    frodo976_pke::decrypt(_skey, _enc, _dec);

    benchmark::DoNotOptimize(_skey);
    benchmark::DoNotOptimize(_enc);
    benchmark::DoNotOptimize(_dec);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark execution of Frodo1344 PKE's key generation algorithm.
inline void
frodo1344_pke_keygen(benchmark::State& state)
{
  constexpr size_t SEED_A_LEN = 16;
  constexpr size_t SEED_SE_LEN = 32;

  std::vector<uint8_t> seedA(SEED_A_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> pkey(frodo1344_pke::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo1344_pke::SEC_KEY_LEN, 0);

  std::span<uint8_t, SEED_A_LEN> _seedA{ seedA };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, frodo1344_pke::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo1344_pke::SEC_KEY_LEN> _skey{ skey };

  prng::prng_t prng;

  prng.read(_seedA.data(), SEED_A_LEN);
  prng.read(_seedSE.data(), SEED_SE_LEN);

  for (auto _ : state) {
    frodo1344_pke::keygen(_seedA, _seedSE, _pkey, _skey);

    benchmark::DoNotOptimize(_seedA);
    benchmark::DoNotOptimize(_seedSE);
    benchmark::DoNotOptimize(_pkey);
    benchmark::DoNotOptimize(_skey);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark execution of Frodo1344 PKE's encryption algorithm.
inline void
frodo1344_pke_encrypt(benchmark::State& state)
{
  constexpr size_t SEED_A_LEN = 16;
  constexpr size_t SEED_SE_LEN = 32;
  constexpr size_t MLEN = 32;

  std::vector<uint8_t> seedA(SEED_A_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> pkey(frodo1344_pke::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo1344_pke::SEC_KEY_LEN, 0);
  std::vector<uint8_t> msg(MLEN, 0);
  std::vector<uint8_t> enc(frodo1344_pke::CIPHER_LEN, 0);

  std::span<uint8_t, SEED_A_LEN> _seedA{ seedA };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, frodo1344_pke::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo1344_pke::SEC_KEY_LEN> _skey{ skey };
  std::span<uint8_t, MLEN> _msg{ msg };
  std::span<uint8_t, frodo1344_pke::CIPHER_LEN> _enc{ enc };

  prng::prng_t prng;

  prng.read(_seedA.data(), SEED_A_LEN);
  prng.read(_seedSE.data(), SEED_SE_LEN);
  prng.read(_msg.data(), MLEN);

  frodo1344_pke::keygen(_seedA, _seedSE, _pkey, _skey);

  for (auto _ : state) {
    frodo1344_pke::encrypt(_seedSE, _pkey, _msg, _enc);

    benchmark::DoNotOptimize(_seedSE);
    benchmark::DoNotOptimize(_pkey);
    benchmark::DoNotOptimize(_msg);
    benchmark::DoNotOptimize(_enc);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark execution of Frodo1344 PKE's decryption algorithm.
inline void
frodo1344_pke_decrypt(benchmark::State& state)
{
  constexpr size_t SEED_A_LEN = 16;
  constexpr size_t SEED_SE_LEN = 32;
  constexpr size_t MLEN = 32;

  std::vector<uint8_t> seedA(SEED_A_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> pkey(frodo1344_pke::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo1344_pke::SEC_KEY_LEN, 0);
  std::vector<uint8_t> msg(MLEN, 0);
  std::vector<uint8_t> enc(frodo1344_pke::CIPHER_LEN, 0);
  std::vector<uint8_t> dec(MLEN, 0);

  std::span<uint8_t, SEED_A_LEN> _seedA{ seedA };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, frodo1344_pke::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo1344_pke::SEC_KEY_LEN> _skey{ skey };
  std::span<uint8_t, MLEN> _msg{ msg };
  std::span<uint8_t, frodo1344_pke::CIPHER_LEN> _enc{ enc };
  std::span<uint8_t, MLEN> _dec{ dec };

  prng::prng_t prng;

  prng.read(_seedA.data(), SEED_A_LEN);
  prng.read(_seedSE.data(), SEED_SE_LEN);
  prng.read(_msg.data(), MLEN);

  frodo1344_pke::keygen(_seedA, _seedSE, _pkey, _skey);
  frodo1344_pke::encrypt(_seedSE, _pkey, _msg, _enc);

  for (auto _ : state) {
    frodo1344_pke::decrypt(_skey, _enc, _dec);

    benchmark::DoNotOptimize(_skey);
    benchmark::DoNotOptimize(_enc);
    benchmark::DoNotOptimize(_dec);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

}
