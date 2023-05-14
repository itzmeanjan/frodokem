#pragma once
#include "encoding.hpp"
#include "matrix.hpp"
#include "packing.hpp"
#include "params.hpp"
#include "sampling.hpp"
#include "shake128.hpp"
#include "shake256.hpp"
#include "utils.hpp"
#include "zq.hpp"
#include <array>
#include <span>

// Frodo Public Key Encryption
namespace pke {

namespace utils = frodo_utils;

// Given a uniformly random seed seedA and another uniformly drawn random seed
// seedSE, this routine can be used for deterministically computing Frodo public
// key encryption scheme's public/ private key pair, following algorithm 9 of
// FrodoKEM specification.
template<const size_t n,
         const size_t n_bar,
         const size_t len_seed_A,
         const size_t len_seed_SE,
         const size_t len_χ,
         const uint32_t q,
         const size_t b>
inline void
keygen(std::span<const uint8_t, (len_seed_A + 7) / 8> seedA,
       std::span<const uint8_t, (len_seed_SE + 7) / 8> seedSE,
       std::span<uint8_t, utils::pke_pub_key_len(n, n_bar, len_seed_A, q)> pkey,
       std::span<uint8_t, utils::pke_sec_key_len(n, n_bar, q)> skey)
  requires(frodo_params::check_frodo_pke_keygen_params(n,
                                                       n_bar,
                                                       len_seed_A,
                                                       len_seed_SE,
                                                       len_χ,
                                                       q,
                                                       b))
{
  auto A = matrix::matrix<n, n, q>::template generate<len_seed_A>(seedA);

  std::array<uint8_t, 1 + seedSE.size()> buf{};
  std::array<uint8_t, (2 * n * n_bar * len_χ + 7) / 8> dig{};

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

  constexpr size_t off = (n * n_bar * len_χ + 7) / 8;

  std::span<uint8_t, dig.size()> dspan{ dig };
  auto sspan0 = dspan.template subspan<0, off>();
  auto sspan1 = dspan.template subspan<off, dspan.size() - off>();

  using namespace sampling;

  auto S_transposed = sample_matrix<n, n_bar, n, len_χ, q, b>(sspan0);
  auto E = sample_matrix<n, n, n_bar, len_χ, q, b>(sspan1);

  auto S = S_transposed.transpose();
  auto B = A * S + E;

  constexpr size_t rm_pk_bytes = pkey.size() - seedA.size();

  std::memcpy(pkey.data(), seedA.data(), seedA.size());
  packing::pack(B, pkey.template subspan<seedA.size(), rm_pk_bytes>());
  packing::pack(S_transposed, skey);
}

// Given a uniformly random seed seedSE, Frodo public key and l -bits message M,
// this routine can be used for encrypting M and computing cipher text,
// following algorithm 10 of FrodoKEM specification.
template<const size_t n,
         const size_t l,
         const size_t m_bar,
         const size_t n_bar,
         const size_t lseed_A,
         const size_t lseed_SE,
         const size_t len_χ,
         const uint32_t q,
         const size_t b>
inline void
encrypt(
  std::span<const uint8_t, (lseed_SE + 7) / 8> seedSE,
  std::span<const uint8_t, utils::pke_pub_key_len(n, n_bar, lseed_A, q)> pkey,
  std::span<const uint8_t, (l + 7) / 8> msg,
  std::span<uint8_t, utils::pke_cipher_text_len(n, m_bar, n_bar, q)> enc)
  requires(frodo_params::check_frodo_pke_encrypt_params(n,
                                                        l,
                                                        m_bar,
                                                        n_bar,
                                                        lseed_A,
                                                        lseed_SE,
                                                        len_χ,
                                                        q,
                                                        b))
{
  auto seedA = pkey.template subspan<0, (lseed_A + 7) / 8>();
  auto A = matrix::matrix<n, n, q>::template generate<lseed_A>(seedA);

  std::array<uint8_t, 1 + seedSE.size()> buf{};
  std::array<uint8_t, ((2 * m_bar * n + m_bar * n_bar) * len_χ + 7) / 8> dig{};

  buf[0] = 0x96;
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

  constexpr size_t off0 = (m_bar * n * len_χ + 7) / 8;
  constexpr size_t off1 = off0 + (m_bar * n * len_χ + 7) / 8;

  std::span<uint8_t, dig.size()> dspan{ dig };
  auto sspan0 = dspan.template subspan<0, off0>();
  auto sspan1 = dspan.template subspan<off0, off1 - off0>();
  auto sspan2 = dspan.template subspan<off1, dspan.size() - off1>();

  using namespace sampling;

  auto S_prime = sample_matrix<n, m_bar, n, len_χ, q, b>(sspan0);
  auto E_prime = sample_matrix<n, m_bar, n, len_χ, q, b>(sspan1);
  auto E_dprime = sample_matrix<n, m_bar, n_bar, len_χ, q, b>(sspan2);

  auto B_prime = S_prime * A + E_prime;

  constexpr size_t rm_pk_bytes = pkey.size() - seedA.size();
  auto pkey_sspan = pkey.template subspan<seedA.size(), rm_pk_bytes>();
  auto B = packing::unpack<n, n_bar, q>(pkey_sspan);

  auto V = S_prime * B + E_dprime;

  auto encoded = encoding::encode<m_bar, n_bar, q, b>(msg);
  auto C2 = V + encoded;

  constexpr size_t coff = (m_bar * n * frodo_utils::log2(q) + 7) / 8;

  packing::pack(B_prime, enc.template subspan<0, coff>());
  packing::pack(C2, enc.template subspan<coff, enc.size() - coff>());
}

// Given a cipher text and Frodo PKE secret key of respective public key, this
// routine can be used for decrypting l -bits message, computing plain text,
// following algorithm 11 of FrodoKEM specification.
template<const size_t n,
         const size_t l,
         const size_t m_bar,
         const size_t n_bar,
         const uint32_t q,
         const size_t b>
inline void
decrypt(
  std::span<const uint8_t, utils::pke_sec_key_len(n, n_bar, q)> skey,
  std::span<const uint8_t, utils::pke_cipher_text_len(n, m_bar, n_bar, q)> enc,
  std::span<uint8_t, (l + 7) / 8> msg)
  requires(
    frodo_params::check_frodo_pke_decrypt_params(n, l, m_bar, n_bar, q, b))
{
  auto S_transposed = packing::unpack<n_bar, n, q>(skey);
  auto S = S_transposed.transpose();

  constexpr size_t coff = (m_bar * n * frodo_utils::log2(q) + 7) / 8;

  auto sspan0 = enc.template subspan<0, coff>();
  auto sspan1 = enc.template subspan<coff, enc.size() - coff>();

  auto C1 = packing::unpack<m_bar, n, q>(sspan0);
  auto C2 = packing::unpack<m_bar, n_bar, q>(sspan1);

  auto M = C2 - C1 * S;

  encoding::decode<m_bar, n_bar, q, b>(M, msg);
}

}
