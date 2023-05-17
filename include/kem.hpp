#pragma once
#include "encoding.hpp"
#include "matrix.hpp"
#include "packing.hpp"
#include "sampling.hpp"
#include "shake128.hpp"
#include "shake256.hpp"
#include "subtle.hpp"
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

  std::span<uint8_t, dig.size()> _dig{ dig };

  constexpr size_t doff = (n * n̄ * len_χ + 7) / 8;
  auto _dig0 = _dig.template subspan<0, doff>();
  auto S_transposed = sampling::sample_matrix<n, n̄, n, len_χ, q, b>(_dig0);

  auto _dig1 = _dig.template subspan<doff, _dig.size() - doff>();
  auto E = sampling::sample_matrix<n, n, n̄, len_χ, q, b>(_dig1);

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

// Given a uniformly random key μ and a Frodo KEM public key ( for which the
// cipher text is going to be computed i.e. only corresponding private key can
// be used for decrypting the cipher text ), this routine can be used for
// computing a cipher text and a shared secret, following algorithm 13 of
// FrodoKEM specification.
template<const size_t n,
         const size_t m̄,
         const size_t n̄,
         const size_t lseed_A,
         const size_t lseed_SE,
         const size_t len_ss,
         const size_t len_k,
         const size_t len_μ,
         const size_t len_pkh,
         const size_t len_χ,
         const uint32_t q,
         const size_t b>
inline void
encaps(std::span<const uint8_t, (len_μ + 7) / 8> μ,
       std::span<const uint8_t, kem_pub_key_len(n, n̄, lseed_A, q)> pkey,
       std::span<uint8_t, kem_cipher_text_len(n, m̄, n̄, q)> enc,
       std::span<uint8_t, (len_ss + 7) / 8> ss)
{
  std::array<uint8_t, (len_pkh + 7) / 8> pkh{};

  if constexpr (n == 640) {
    shake128::shake128 hasher;

    hasher.hash(pkey.data(), pkey.size());
    hasher.read(pkh.data(), pkh.size());
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256 hasher;

    hasher.hash(pkey.data(), pkey.size());
    hasher.read(pkh.data(), pkh.size());
  }

  std::array<uint8_t, (lseed_SE + len_k + 7) / 8> rand_bytes{};

  if constexpr (n == 640) {
    shake128::shake128<true> hasher;

    hasher.absorb(pkh.data(), pkh.size());
    hasher.absorb(μ.data(), μ.size());
    hasher.finalize();
    hasher.read(rand_bytes.data(), rand_bytes.size());
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256<true> hasher;

    hasher.absorb(pkh.data(), pkh.size());
    hasher.absorb(μ.data(), μ.size());
    hasher.finalize();
    hasher.read(rand_bytes.data(), rand_bytes.size());
  }

  std::array<uint8_t, 1 + (lseed_SE + 7) / 8> buf{};
  std::array<uint8_t, ((2 * m̄ * n + m̄ * n̄) * len_χ + 7) / 8> dig{};

  buf[0] = 0x96;
  std::memcpy(buf.data() + 1, rand_bytes.data(), (lseed_SE + 7) / 8);

  if constexpr (n == 640) {
    shake128::shake128 hasher;

    hasher.hash(buf.data(), buf.size());
    hasher.read(dig.data(), dig.size());
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256 hasher;

    hasher.hash(buf.data(), buf.size());
    hasher.read(dig.data(), dig.size());
  }

  std::span<uint8_t, dig.size()> _dig{ dig };

  constexpr size_t doff0 = (m̄ * n * len_χ + 7) / 8;
  auto _dig0 = _dig.template subspan<0, doff0>();
  auto S_prime = sampling::sample_matrix<n, m̄, n, len_χ, q, b>(_dig0);

  constexpr size_t doff1 = doff0 + (m̄ * n * len_χ + 7) / 8;
  auto _dig1 = _dig.template subspan<doff0, doff1 - doff0>();
  auto E_prime = sampling::sample_matrix<n, m̄, n, len_χ, q, b>(_dig1);

  auto pkey0 = pkey.template subspan<0, (lseed_A + 7) / 8>();
  auto A = matrix::matrix<n, n, q>::template generate<lseed_A>(pkey0);

  auto B_prime = S_prime * A + E_prime;

  auto _dig2 = _dig.template subspan<doff1, _dig.size() - doff1>();
  auto E_dprime = sampling::sample_matrix<n, m̄, n̄, len_χ, q, b>(_dig2);

  constexpr size_t pkoff = pkey0.size();
  auto pkey1 = pkey.template subspan<pkoff, pkey.size() - pkoff>();
  auto B = packing::unpack<n, n̄, q>(pkey1);

  auto V = S_prime * B + E_dprime;

  auto M = encoding::encode<m̄, n̄, q, b>(μ);
  auto C = V + M;

  auto enc0 = enc.template subspan<0, (m̄ * n * log2(q) + 7) / 8>();
  packing::pack(B_prime, enc0);

  auto enc1 = enc.template subspan<enc0.size(), enc.size() - enc0.size()>();
  packing::pack(C, enc1);

  if constexpr (n == 640) {
    shake128::shake128<true> hasher;

    hasher.absorb(enc.data(), enc.size());
    hasher.absorb(rand_bytes.data() + (lseed_SE + 7) / 8, (len_k + 7) / 8);
    hasher.finalize();
    hasher.read(ss.data(), ss.size());
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256<true> hasher;

    hasher.absorb(enc.data(), enc.size());
    hasher.absorb(rand_bytes.data() + (lseed_SE + 7) / 8, (len_k + 7) / 8);
    hasher.finalize();
    hasher.read(ss.data(), ss.size());
  }
}

// Given a FrodoKEM cipher text and secret key, which is associated with the
// public key, using which the cipher text was computed, this routine can be
// used for decrypting the cipher text, recovering shared secret, following
// algorithm 14 of FrodoKEM specification.
template<const size_t n,
         const size_t m̄,
         const size_t n̄,
         const size_t lseed_A,
         const size_t lseed_SE,
         const size_t len_s,
         const size_t len_ss,
         const size_t len_k,
         const size_t len_μ,
         const size_t len_pkh,
         const size_t len_χ,
         const uint32_t q,
         const size_t b>
inline void
decaps(std::span<const uint8_t,
                 kem_sec_key_len(n, n̄, len_s, lseed_A, len_pkh, q)> skey,
       std::span<const uint8_t, kem_cipher_text_len(n, m̄, n̄, q)> enc,
       std::span<uint8_t, (len_ss + 7) / 8> ss)
{
  auto enc0 = enc.template subspan<0, (m̄ * n * log2(q) + 7) / 8>();
  auto B_prime = packing::unpack<m̄, n, q>(enc0);

  auto enc1 = enc.template subspan<enc0.size(), enc.size() - enc0.size()>();
  auto C = packing::unpack<m̄, n̄, q>(enc1);

  // = s
  auto skey0 = skey.template subspan<0, (len_s + 7) / 8>();

  // = seedA
  constexpr size_t soff0 = skey0.size();
  auto skey1 = skey.template subspan<soff0, (lseed_A + 7) / 8>();

  // = b
  constexpr size_t soff1 = soff0 + skey1.size();
  auto skey2 = skey.template subspan<soff1, (n * n̄ * log2(q) + 7) / 8>();

  // = S_transposed
  constexpr size_t soff2 = soff1 + skey2.size();
  auto skey3 = skey.template subspan<soff2, (n̄ * n * log2(q) + 7) / 8>();
  auto S_transposed = packing::unpack<n̄, n, q>(skey3);
  auto S = S_transposed.transpose();

  // = pkh
  constexpr size_t soff3 = soff2 + skey3.size();
  auto skey4 = skey.template subspan<soff3, (len_pkh + 7) / 8>();

  auto M = C - B_prime * S;

  std::array<uint8_t, (len_μ + 7) / 8> μ_prime{};
  encoding::decode<m̄, n̄, q, b>(M, μ_prime);

  std::array<uint8_t, (lseed_SE + len_k + 7) / 8> rand_bytes{};

  if constexpr (n == 640) {
    shake128::shake128<true> hasher;

    hasher.absorb(skey4.data(), skey4.size());
    hasher.absorb(μ_prime.data(), μ_prime.size());
    hasher.finalize();
    hasher.read(rand_bytes.data(), rand_bytes.size());
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256<true> hasher;

    hasher.absorb(skey4.data(), skey4.size());
    hasher.absorb(μ_prime.data(), μ_prime.size());
    hasher.finalize();
    hasher.read(rand_bytes.data(), rand_bytes.size());
  }

  std::array<uint8_t, 1 + (lseed_SE + 7) / 8> buf{};
  std::array<uint8_t, ((2 * m̄ * n + m̄ * n̄) * len_χ + 7) / 8> dig{};

  buf[0] = 0x96;
  std::memcpy(buf.data() + 1, rand_bytes.data(), (lseed_SE + 7) / 8);

  if constexpr (n == 640) {
    shake128::shake128 hasher;

    hasher.hash(buf.data(), buf.size());
    hasher.read(dig.data(), dig.size());
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256 hasher;

    hasher.hash(buf.data(), buf.size());
    hasher.read(dig.data(), dig.size());
  }

  std::span<uint8_t, dig.size()> _dig{ dig };

  constexpr size_t doff0 = (m̄ * n * len_χ + 7) / 8;
  auto _dig0 = _dig.template subspan<0, doff0>();
  auto S_prime = sampling::sample_matrix<n, m̄, n, len_χ, q, b>(_dig0);

  constexpr size_t doff1 = doff0 + (m̄ * n * len_χ + 7) / 8;
  auto _dig1 = _dig.template subspan<doff0, doff1 - doff0>();
  auto E_prime = sampling::sample_matrix<n, m̄, n, len_χ, q, b>(_dig1);

  auto A = matrix::matrix<n, n, q>::template generate<lseed_A>(skey1);
  auto B_dprime = S_prime * A + E_prime;

  auto _dig2 = _dig.template subspan<doff1, _dig.size() - doff1>();
  auto E_dprime = sampling::sample_matrix<n, m̄, n̄, len_χ, q, b>(_dig2);

  auto B = packing::unpack<n, n̄, q>(skey2);
  auto V = S_prime * B + E_dprime;
  auto C_prime = V + M;

  // Constant-time implementation of step 16
  // --- begins ---
  const auto br0 = B_prime.template ct_equal<uint32_t>(B_dprime);
  const auto br1 = C.template ct_equal<uint32_t>(C_prime);
  const auto br = br0 & br1;

  static_assert(len_k == len_s,
                "See step 16 of algorithm 14 and table 4 of specification !");

  auto k_prime = rand_bytes.data() + (lseed_SE + 7) / 8;
  std::array<uint8_t, (len_k + 7) / 8> k̄{};

  for (size_t i = 0; i < k̄.size(); i++) {
    k̄[i] = subtle::ct_select(br, k_prime[i], skey0[i]);
  }
  // --- ends ---

  if constexpr (n == 640) {
    shake128::shake128<true> hasher;

    hasher.absorb(enc.data(), enc.size());
    hasher.absorb(k̄.data(), k̄.size());
    hasher.finalize();
    hasher.read(ss.data(), ss.size());
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256<true> hasher;

    hasher.absorb(enc.data(), enc.size());
    hasher.absorb(k̄.data(), k̄.size());
    hasher.finalize();
    hasher.read(ss.data(), ss.size());
  }
}

}
