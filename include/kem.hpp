#pragma once
#include "encoding.hpp"
#include "matrix.hpp"
#include "packing.hpp"
#include "params.hpp"
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
// - `s` of len_sec -bits
// - `seedSE` of len_SE -bits
// - `z` of len_A -bits
//
// as input, this routine can be used for deterministically generating a new
// Frodo KEM public/ private keypair, following algorithm definition in
// section 8.1 of FrodoKEM specification.
template<const size_t n,
         const size_t n̄,
         const size_t len_sec,
         const size_t len_SE,
         const size_t len_A,
         const size_t B,
         const size_t D>
inline void
keygen(std::span<const uint8_t, len_sec / 8> s,
       std::span<const uint8_t, len_SE / 8> seedSE,
       std::span<const uint8_t, len_A / 8> z,
       std::span<uint8_t, kem_pub_key_len(n, n̄, len_A, D)> pkey,
       std::span<uint8_t, kem_sec_key_len(n, n̄, len_sec, len_A, D)> skey)
{
  std::array<uint8_t, len_A / 8> seedA{};

  if constexpr (n == 640) {
    shake128::shake128 hasher;

    hasher.hash(z.data(), z.size());
    hasher.read(seedA.data(), seedA.size());
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256 hasher;

    hasher.hash(z.data(), z.size());
    hasher.read(seedA.data(), seedA.size());
  }

  auto A = matrix::matrix<n, n, D>::template generate<len_A>(seedA);

  std::array<uint8_t, 1 + seedSE.size()> buf{};
  std::array<uint8_t, (32 * n * n̄) / 8> dig{};

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

  auto _dig0 = _dig.template subspan<0, 2 * n * n̄>();
  auto S_transposed = sampling::sample_matrix<n, n̄, n, D>(_dig0);

  auto _dig1 = _dig.template subspan<_dig0.size(), 2 * n * n̄>();
  auto E = sampling::sample_matrix<n, n, n̄, D>(_dig1);

  auto S = S_transposed.transpose();
  auto B_mat = A * S + E;

  // --- serialize public key ---
  auto pkey0 = pkey.template subspan<0, seedA.size()>();
  std::memcpy(pkey0.data(), seedA.data(), pkey0.size());

  auto pkey1 = pkey.template subspan<pkey0.size(), (D * n * n̄) / 8>();
  packing::pack(B_mat, pkey1);
  // --- done ---

  std::array<uint8_t, len_sec / 8> pkh{};

  if constexpr (n == 640) {
    shake128::shake128 hasher;

    hasher.hash(pkey.data(), pkey.size());
    hasher.read(pkh.data(), pkh.size());
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256 hasher;

    hasher.hash(pkey.data(), pkey.size());
    hasher.read(pkh.data(), pkh.size());
  }

  // --- serialize secret key ---
  auto skey0 = skey.template subspan<0, s.size()>();
  std::memcpy(skey0.data(), s.data(), skey0.size());

  constexpr size_t skoff0 = skey0.size();
  auto skey1 = skey.template subspan<skoff0, pkey.size()>();
  std::memcpy(skey1.data(), pkey.data(), skey1.size());

  constexpr size_t skoff1 = skoff0 + skey1.size();
  auto skey2 = skey.template subspan<skoff1, n̄ * n * 2>();
  S_transposed.write_as_le_bytes(skey2);

  constexpr size_t skoff2 = skoff1 + skey2.size();
  auto skey3 = skey.template subspan<skoff2, pkh.size()>();
  std::memcpy(skey3.data(), pkh.data(), pkh.size());
  // --- done ---
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
         const size_t d,
         const size_t b>
inline void
encaps(std::span<const uint8_t, (len_μ + 7) / 8> μ,
       std::span<const uint8_t, kem_pub_key_len(n, n̄, lseed_A, d)> pkey,
       std::span<uint8_t, kem_cipher_text_len(n, m̄, n̄, d)> enc,
       std::span<uint8_t, (len_ss + 7) / 8> ss)
  requires(frodo_params::check_frodo_encaps_params(n,
                                                   m̄,
                                                   n̄,
                                                   lseed_A,
                                                   lseed_SE,
                                                   len_ss,
                                                   len_k,
                                                   len_μ,
                                                   len_pkh,
                                                   len_χ,
                                                   d,
                                                   b))
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
  auto S_prime = sampling::sample_matrix<n, m̄, n, len_χ, d>(_dig0);

  constexpr size_t doff1 = doff0 + (m̄ * n * len_χ + 7) / 8;
  auto _dig1 = _dig.template subspan<doff0, doff1 - doff0>();
  auto E_prime = sampling::sample_matrix<n, m̄, n, len_χ, d>(_dig1);

  auto pkey0 = pkey.template subspan<0, (lseed_A + 7) / 8>();
  auto A = matrix::matrix<n, n, d>::template generate<lseed_A>(pkey0);

  auto B_prime = S_prime * A + E_prime;

  auto _dig2 = _dig.template subspan<doff1, _dig.size() - doff1>();
  auto E_dprime = sampling::sample_matrix<n, m̄, n̄, len_χ, d>(_dig2);

  constexpr size_t pkoff = pkey0.size();
  auto pkey1 = pkey.template subspan<pkoff, pkey.size() - pkoff>();
  auto B = packing::unpack<n, n̄, d>(pkey1);

  auto V = S_prime * B + E_dprime;

  auto M = encoding::encode<m̄, n̄, d, b>(μ);
  auto C = V + M;

  auto enc0 = enc.template subspan<0, (m̄ * n * d + 7) / 8>();
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
         const size_t d,
         const size_t b>
inline void
decaps(std::span<const uint8_t,
                 kem_sec_key_len(n, n̄, len_s, lseed_A, len_pkh, d)> skey,
       std::span<const uint8_t, kem_cipher_text_len(n, m̄, n̄, d)> enc,
       std::span<uint8_t, (len_ss + 7) / 8> ss)
  requires(frodo_params::check_frodo_decaps_params(n,
                                                   m̄,
                                                   n̄,
                                                   lseed_A,
                                                   lseed_SE,
                                                   len_s,
                                                   len_ss,
                                                   len_k,
                                                   len_μ,
                                                   len_pkh,
                                                   len_χ,
                                                   d,
                                                   b))
{
  auto enc0 = enc.template subspan<0, (m̄ * n * d + 7) / 8>();
  auto B_prime = packing::unpack<m̄, n, d>(enc0);

  auto enc1 = enc.template subspan<enc0.size(), enc.size() - enc0.size()>();
  auto C = packing::unpack<m̄, n̄, d>(enc1);

  // = s
  auto skey0 = skey.template subspan<0, (len_s + 7) / 8>();

  // = seedA
  constexpr size_t soff0 = skey0.size();
  auto skey1 = skey.template subspan<soff0, (lseed_A + 7) / 8>();

  // = b
  constexpr size_t soff1 = soff0 + skey1.size();
  auto skey2 = skey.template subspan<soff1, (n * n̄ * d + 7) / 8>();

  // = S_transposed
  constexpr size_t soff2 = soff1 + skey2.size();
  auto skey3 = skey.template subspan<soff2, n̄ * n * 2>();
  auto S_transposed = matrix::matrix<n̄, n, d>::read_from_le_bytes(skey3);
  auto S = S_transposed.transpose();

  // = pkh
  constexpr size_t soff3 = soff2 + skey3.size();
  auto skey4 = skey.template subspan<soff3, skey.size() - soff3>();

  auto M = C - B_prime * S;

  std::array<uint8_t, (len_μ + 7) / 8> μ_prime{};
  encoding::decode<m̄, n̄, d, b>(M, μ_prime);

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
  std::memcpy(buf.data() + 1, rand_bytes.data(), buf.size() - 1);

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
  auto S_prime = sampling::sample_matrix<n, m̄, n, len_χ, d>(_dig0);

  constexpr size_t doff1 = doff0 + (m̄ * n * len_χ + 7) / 8;
  auto _dig1 = _dig.template subspan<doff0, doff1 - doff0>();
  auto E_prime = sampling::sample_matrix<n, m̄, n, len_χ, d>(_dig1);

  auto A = matrix::matrix<n, n, d>::template generate<lseed_A>(skey1);
  auto B_dprime = S_prime * A + E_prime;

  auto _dig2 = _dig.template subspan<doff1, _dig.size() - doff1>();
  auto E_dprime = sampling::sample_matrix<n, m̄, n̄, len_χ, d>(_dig2);

  auto B = packing::unpack<n, n̄, d>(skey2);
  auto V = S_prime * B + E_dprime;

  auto M_prime = encoding::encode<m̄, n̄, d, b>(μ_prime);
  auto C_prime = V + M_prime;

  // Constant-time implementation of step 16
  // --- begins ---
  const uint32_t br0 = B_prime.ct_equal(B_dprime);
  const uint32_t br1 = C.ct_equal(C_prime);
  const uint32_t br = br0 & br1;

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
