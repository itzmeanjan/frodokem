#pragma once
#include "matrix.hpp"
#include "packing.hpp"
#include "sampling.hpp"
#include "shake128.hpp"
#include "shake256.hpp"
#include "utils.hpp"
#include "zq.hpp"
#include <array>
#include <cstring>
#include <span>

// Frodo Key Encapsulation Mechanism
namespace kem {

using namespace frodo_utils;

// Given following three uniformly random sampled seeds
//
// - `s` of len_s -bits
// - `seedSE` of len_seed_SE -bits
// - `z` of len_z -bits
//
// as input, this routine can be used for deterministically generating a new
// Frodo KEM public/ private keypair, following algorithm 12 of FrodoKEM
// specification.
template<const size_t n,
         const size_t n̄,
         const size_t len_seed_A,
         const size_t len_seed_SE,
         const size_t len_s,
         const size_t len_z,
         const size_t len_pkh,
         const size_t len_χ,
         const uint32_t q,
         const size_t b>
inline void
keygen(
  std::span<const uint8_t, (len_s + 7) / 8> s,
  std::span<const uint8_t, (len_seed_SE + 7) / 8> seedSE,
  std::span<const uint8_t, (len_z + 7) / 8> z,
  std::span<uint8_t, kem_pub_key_len(n, n̄, len_seed_A, q)> pkey,
  std::span<uint8_t, kem_sec_key_len(n, n̄, len_s, len_seed_A, len_pkh, q)> skey)
{
  std::array<uint8_t, (len_seed_A + 7) / 8> seedA{};

  if constexpr (n == 640) {
    shake128::shake128 hasher;

    hasher.hash(z.data(), z.size());
    hasher.read(seedA.data(), seedA.size());
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256 hasher;

    hasher.hash(z.data(), z.size());
    hasher.read(seedA.data(), seedA.size());
  }

  auto A = matrix::matrix<n, n, q>::template generate<len_seed_A>(seedA);

  std::array<uint8_t, 1 + seedSE.size()> buf{};
  std::array<uint8_t, (2 * n * n̄ * len_χ + 7) / 8> dig{};

  buf[0] = 0x5f;
  std::memcpy(buf.data() + 1, seedSE.data(), seedSE.size());

  if constexpr (n == 640) {
    shake128::shake128 hasher;

    hasher.hash(buf.data(), buf.size());
    hasher.read(dig.data(), dig.size());
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256 hasher;

    hasher.hash(buf.data(), buf.size());
    hasher.read(dig.data(), dig.size());
  }

  constexpr size_t doff = (n * n̄ * len_χ + 7) / 8;

  std::span<uint8_t, dig.size()> _dig{ dig };
  auto _dig0 = _dig.template subspan<0, doff>();
  auto _dig1 = _dig.template subspan<doff, _dig.size() - doff>();

  using namespace sampling;

  auto S_transposed = sample_matrix<n, n̄, n, len_χ, q, b>(_dig0);
  auto E = sample_matrix<n, n, n̄, len_χ, q, b>(_dig1);

  auto S = S_transposed.transpose();
  auto B = A * S + E;

  std::array<uint8_t, (n * n̄ * log2(q) + 7) / 8> packed_b{};
  packing::pack(B, packed_b);

  std::array<uint8_t, (len_pkh + 7) / 8> pkh{};

  if constexpr (n == 640) {
    shake128::shake128<true> hasher;

    hasher.absorb(seedA.data(), seedA.size());
    hasher.absorb(packed_b.data(), packed_b.size());
    hasher.finalize();
    hasher.read(pkh.data(), pkh.size());
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256<true> hasher;

    hasher.absorb(seedA.data(), seedA.size());
    hasher.absorb(packed_b.data(), packed_b.size());
    hasher.finalize();
    hasher.read(pkh.data(), pkh.size());
  }

  // serialize public key
  auto pkey0 = pkey.template subspan<0, seedA.size()>();
  std::memcpy(pkey0.data(), seedA.data(), pkey0.size());

  constexpr size_t pkoff = pkey0.size();
  auto pkey1 = pkey.template subspan<pkoff, pkey.size() - pkoff>();
  std::memcpy(pkey1.data(), packed_b.data(), pkey1.size());

  // serialize secret key
  auto skey0 = skey.template subspan<0, s.size()>();
  std::memcpy(skey0.data(), s.data(), skey0.size());

  constexpr size_t skoff0 = skey0.size();
  auto skey1 = skey.template subspan<skoff0, pkey.size()>();
  std::memcpy(skey1.data(), pkey.data(), skey1.size());

  constexpr size_t skoff1 = skoff0 + skey1.size();
  constexpr size_t packed_s_len = (n̄ * n * log2(q) + 7) / 8;
  auto skey2 = skey.template subspan<skoff1, packed_s_len>();
  packing::pack(S_transposed, skey2);

  constexpr size_t skoff2 = skoff1 + skey2.size();
  auto skey3 = skey.template subspan<skoff2, pkh.size()>();
  std::memcpy(skey3.data(), pkh.data(), pkh.size());
}

}
