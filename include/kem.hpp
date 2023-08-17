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
  requires(
    frodo_params::check_keygen_params(n, n̄, len_sec, len_SE, len_A, B, D))
{
  std::array<uint8_t, len_A / 8> seedA{};

  if constexpr (n == 640) {
    shake128::shake128_t hasher;

    hasher.absorb(z);
    hasher.finalize();
    hasher.squeeze(seedA);
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256_t hasher;

    hasher.absorb(z);
    hasher.finalize();
    hasher.squeeze(seedA);
  }

  auto A = matrix::matrix<n, n, D>::template generate<len_A>(seedA);

  std::array<uint8_t, 1 + seedSE.size()> buf{};
  std::array<uint8_t, (32 * n * n̄) / 8> dig{};

  buf[0] = 0x5f;
  std::memcpy(buf.data() + 1, seedSE.data(), seedSE.size());

  if constexpr (n == 640) {
    shake128::shake128_t hasher;

    hasher.absorb(buf);
    hasher.finalize();
    hasher.squeeze(dig);
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256_t hasher;

    hasher.absorb(buf);
    hasher.finalize();
    hasher.squeeze(dig);
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
    shake128::shake128_t hasher;

    hasher.absorb(pkey);
    hasher.finalize();
    hasher.squeeze(pkh);
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256_t hasher;

    hasher.absorb(pkey);
    hasher.finalize();
    hasher.squeeze(pkh);
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

// Given a uniformly random values μ and salt, along with a target Frodo KEM
// public key ( for which the cipher text is going to be computed i.e. only
// corresponding private key can be used for decrypting the cipher text ), this
// routine can be used for computing a cipher text and a shared secret,
// following algorithm definition in section 8.2 of FrodoKEM specification.
template<const size_t n,
         const size_t n̄,
         const size_t len_sec,
         const size_t len_SE,
         const size_t len_A,
         const size_t len_salt,
         const size_t B,
         const size_t D>
inline void
encaps(std::span<const uint8_t, len_sec / 8> μ,
       std::span<const uint8_t, len_salt / 8> salt,
       std::span<const uint8_t, kem_pub_key_len(n, n̄, len_A, D)> pkey,
       std::span<uint8_t, kem_cipher_text_len(n, n̄, len_salt, D)> enc,
       std::span<uint8_t, len_sec / 8> ss)
  requires(frodo_params::check_encaps_params(n,
                                             n̄,
                                             len_sec,
                                             len_SE,
                                             len_A,
                                             len_salt,
                                             B,
                                             D))
{
  std::array<uint8_t, len_sec / 8> pkh{};

  if constexpr (n == 640) {
    shake128::shake128_t hasher;

    hasher.absorb(pkey);
    hasher.finalize();
    hasher.squeeze(pkh);
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256_t hasher;

    hasher.absorb(pkey);
    hasher.finalize();
    hasher.squeeze(pkh);
  }

  std::array<uint8_t, (len_SE + len_sec) / 8> rand_bytes{};
  auto _rand_bytes = std::span(rand_bytes);

  if constexpr (n == 640) {
    shake128::shake128_t hasher;

    hasher.absorb(pkh);
    hasher.absorb(μ);
    hasher.absorb(salt);
    hasher.finalize();
    hasher.squeeze(_rand_bytes);
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256_t hasher;

    hasher.absorb(pkh);
    hasher.absorb(μ);
    hasher.absorb(salt);
    hasher.finalize();
    hasher.squeeze(_rand_bytes);
  }

  std::array<uint8_t, 1 + len_SE / 8> buf{};
  std::array<uint8_t, ((2 * n̄ * n + n̄ * n̄) * 16) / 8> dig{};

  buf[0] = 0x96;
  std::memcpy(buf.data() + 1, _rand_bytes.data(), len_SE / 8);

  if constexpr (n == 640) {
    shake128::shake128_t hasher;

    hasher.absorb(buf);
    hasher.finalize();
    hasher.squeeze(dig);
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256_t hasher;

    hasher.absorb(buf);
    hasher.finalize();
    hasher.squeeze(dig);
  }

  std::span<uint8_t, dig.size()> _dig{ dig };

  constexpr size_t doff0 = (n̄ * n * 16) / 8;
  auto _dig0 = _dig.template subspan<0, doff0>();
  auto S_prime = sampling::sample_matrix<n, n̄, n, D>(_dig0);

  constexpr size_t doff1 = doff0 + (n̄ * n * 16) / 8;
  auto _dig1 = _dig.template subspan<doff0, doff1 - doff0>();
  auto E_prime = sampling::sample_matrix<n, n̄, n, D>(_dig1);

  auto pkey0 = pkey.template subspan<0, len_A / 8>();
  auto A = matrix::matrix<n, n, D>::template generate<len_A>(pkey0);

  auto B_prime = S_prime * A + E_prime;

  auto _dig2 = _dig.template subspan<doff1, _dig.size() - doff1>();
  auto E_dprime = sampling::sample_matrix<n, n̄, n̄, D>(_dig2);

  constexpr size_t pkoff = pkey0.size();
  auto pkey1 = pkey.template subspan<pkoff, pkey.size() - pkoff>();
  auto B_mat = packing::unpack<n, n̄, D>(pkey1);

  auto V = S_prime * B_mat + E_dprime;

  auto M = encoding::encode<n̄, n̄, D, B>(μ);
  auto C = V + M;

  auto enc0 = enc.template subspan<0, (n̄ * n * D) / 8>();
  packing::pack(B_prime, enc0);

  auto enc1 = enc.template subspan<enc0.size(), (n̄ * n̄ * D) / 8>();
  packing::pack(C, enc1);

  auto enc2 = enc.template subspan<enc0.size() + enc1.size(), salt.size()>();
  std::memcpy(enc2.data(), salt.data(), salt.size());

  if constexpr (n == 640) {
    shake128::shake128_t hasher;

    hasher.absorb(enc);
    hasher.absorb(_rand_bytes.subspan(len_SE / 8, len_sec / 8));
    hasher.finalize();
    hasher.squeeze(ss);
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256_t hasher;

    hasher.absorb(enc);
    hasher.absorb(_rand_bytes.subspan(len_SE / 8, len_sec / 8));
    hasher.finalize();
    hasher.squeeze(ss);
  }
}

// Given a FrodoKEM cipher text and secret key, which is associated with the
// public key, using which the cipher text was computed, this routine can be
// used for decrypting the cipher text, recovering shared secret, following
// algorithm definition in section 8.3 of FrodoKEM specification.
template<const size_t n,
         const size_t n̄,
         const size_t len_sec,
         const size_t len_SE,
         const size_t len_A,
         const size_t len_salt,
         const size_t B,
         const size_t D>
inline void
decaps(std::span<const uint8_t, kem_sec_key_len(n, n̄, len_sec, len_A, D)> skey,
       std::span<const uint8_t, kem_cipher_text_len(n, n̄, len_salt, D)> enc,
       std::span<uint8_t, len_sec / 8> ss)
  requires(frodo_params::check_decaps_params(n,
                                             n̄,
                                             len_sec,
                                             len_SE,
                                             len_A,
                                             len_salt,
                                             B,
                                             D))
{
  // Parse cipher text
  // = c1
  auto enc0 = enc.template subspan<0, (n̄ * n * D) / 8>();
  auto B_prime = packing::unpack<n̄, n, D>(enc0);

  // = c2
  auto enc1 = enc.template subspan<enc0.size(), (n̄ * n̄ * D) / 8>();
  auto C = packing::unpack<n̄, n̄, D>(enc1);

  // = salt
  auto enc2 = enc.template subspan<enc0.size() + enc1.size(), len_salt / 8>();

  // Parse secret key
  // = s
  auto skey0 = skey.template subspan<0, len_sec / 8>();

  // = seedA
  constexpr size_t soff0 = skey0.size();
  auto skey1 = skey.template subspan<soff0, len_A / 8>();

  // = b
  constexpr size_t soff1 = soff0 + skey1.size();
  auto skey2 = skey.template subspan<soff1, (n * n̄ * D) / 8>();

  // = S_transposed
  constexpr size_t soff2 = soff1 + skey2.size();
  auto skey3 = skey.template subspan<soff2, n̄ * n * 2>();
  auto S_transposed = matrix::matrix<n̄, n, D>::read_from_le_bytes(skey3);
  auto S = S_transposed.transpose();

  // = pkh
  constexpr size_t soff3 = soff2 + skey3.size();
  auto skey4 = skey.template subspan<soff3, skey.size() - soff3>();

  auto M = C - B_prime * S;

  std::array<uint8_t, len_sec / 8> μ_prime{};
  encoding::decode<n̄, n̄, D, B>(M, μ_prime);

  std::array<uint8_t, (len_SE + len_sec) / 8> rand_bytes{};

  if constexpr (n == 640) {
    shake128::shake128_t hasher;

    hasher.absorb(skey4);
    hasher.absorb(μ_prime);
    hasher.absorb(enc2);
    hasher.finalize();
    hasher.squeeze(rand_bytes);
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256_t hasher;

    hasher.absorb(skey4);
    hasher.absorb(μ_prime);
    hasher.absorb(enc2);
    hasher.finalize();
    hasher.squeeze(rand_bytes);
  }

  std::array<uint8_t, 1 + (len_SE) / 8> buf{};
  std::array<uint8_t, ((2 * n̄ * n + n̄ * n̄) * 16) / 8> dig{};

  buf[0] = 0x96;
  std::memcpy(buf.data() + 1, rand_bytes.data(), buf.size() - 1);

  if constexpr (n == 640) {
    shake128::shake128_t hasher;

    hasher.absorb(buf);
    hasher.finalize();
    hasher.squeeze(dig);
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256_t hasher;

    hasher.absorb(buf);
    hasher.finalize();
    hasher.squeeze(dig);
  }

  std::span<uint8_t, dig.size()> _dig{ dig };

  constexpr size_t doff0 = (n̄ * n * 16) / 8;
  auto _dig0 = _dig.template subspan<0, doff0>();
  auto S_prime = sampling::sample_matrix<n, n̄, n, D>(_dig0);

  constexpr size_t doff1 = doff0 + (n̄ * n * 16) / 8;
  auto _dig1 = _dig.template subspan<doff0, doff1 - doff0>();
  auto E_prime = sampling::sample_matrix<n, n̄, n, D>(_dig1);

  auto A = matrix::matrix<n, n, D>::template generate<len_A>(skey1);
  auto B_dprime = S_prime * A + E_prime;

  auto _dig2 = _dig.template subspan<doff1, _dig.size() - doff1>();
  auto E_dprime = sampling::sample_matrix<n, n̄, n̄, D>(_dig2);

  auto B_mat = packing::unpack<n, n̄, D>(skey2);
  auto V = S_prime * B_mat + E_dprime;

  auto M_prime = encoding::encode<n̄, n̄, D, B>(μ_prime);
  auto C_prime = V + M_prime;

  // Constant-time implementation of step 15
  // --- begins ---
  const uint32_t br0 = B_prime.ct_equal(B_dprime);
  const uint32_t br1 = C.ct_equal(C_prime);
  const uint32_t br = br0 & br1;

  auto k_prime = rand_bytes.data() + (len_SE / 8);
  std::array<uint8_t, (len_sec + 7) / 8> k̄{};

  for (size_t i = 0; i < k̄.size(); i++) {
    k̄[i] = subtle::ct_select(br, k_prime[i], skey0[i]);
  }
  // --- ends ---

  if constexpr (n == 640) {
    shake128::shake128_t hasher;

    hasher.absorb(enc);
    hasher.absorb(k̄);
    hasher.finalize();
    hasher.squeeze(ss);
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256_t hasher;

    hasher.absorb(enc);
    hasher.absorb(k̄);
    hasher.finalize();
    hasher.squeeze(ss);
  }
}

}
