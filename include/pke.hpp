#pragma once
#include "encoding.hpp"
#include "gen_matrix.hpp"
#include "matrix.hpp"
#include "packing.hpp"
#include "sampling.hpp"
#include "shake128.hpp"
#include "shake256.hpp"
#include "utils.hpp"
#include "zq.hpp"

// Frodo Public Key Encryption
namespace pke {

// Given a uniformly random seed seedA and another uniformly drawn random seed
// seedSE, this routine can be used for deterministically computing Frodo public
// key encryption scheme's public/ private key pair, following algorithm 9 of
// FrodoKEM specification.
template<const size_t n,
         const size_t n_bar,
         const size_t len_seed_A,
         const size_t len_seed_SE,
         const size_t len_χ,
         const uint32_t Q,
         const size_t B>
inline void
keygen(const uint8_t* const __restrict seedA,  // len_seed_A -bits
       const uint8_t* const __restrict seedSE, // len_seed_SE -bits
       uint8_t* const __restrict pkey,
       uint8_t* const __restrict skey)
{
  zq::zq_t<Q> a[n * n];
  gen_matrix::gen<len_seed_A, n>(seedA, a);

  uint8_t buf[1 + (len_seed_SE / 8)];
  uint8_t dig[2 * n * n_bar * (len_χ / 8)];

  buf[0] = 0x5f;
  std::memcpy(buf + 1, seedSE, len_seed_SE / 8);

  if constexpr (n == 640) {
    shake128::shake128 hasher;

    hasher.hash(buf, sizeof(buf));
    hasher.read(dig, sizeof(dig));
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256 hasher;

    hasher.hash(buf, sizeof(buf));
    hasher.read(dig, sizeof(dig));
  }

  zq::zq_t<Q> s_t[n_bar * n];
  zq::zq_t<Q> e[n * n_bar];

  {
    using namespace sampling;

    constexpr size_t off = n * n_bar * (len_χ / 8);

    if constexpr (n == 640) {
      const auto Tχ = Frodo640_Tχ;

      sample_matrix<n_bar, n, len_χ, Q, B>(dig, s_t, Tχ);
      sample_matrix<n, n_bar, len_χ, Q, B>(dig + off, e, Tχ);
    } else if constexpr (n == 976) {
      const auto Tχ = Frodo976_Tχ;

      sample_matrix<n_bar, n, len_χ, Q, B>(dig, s_t, Tχ);
      sample_matrix<n, n_bar, len_χ, Q, B>(dig + off, e, Tχ);
    } else if constexpr (n == 1344) {
      const auto Tχ = Frodo1344_Tχ;

      sample_matrix<n_bar, n, len_χ, Q, B>(dig, s_t, Tχ);
      sample_matrix<n, n_bar, len_χ, Q, B>(dig + off, e, Tχ);
    }
  }

  zq::zq_t<Q> s[n * n_bar];
  matrix::transpose<n_bar, n>(s_t, s);

  zq::zq_t<Q> tmp[n * n_bar];
  zq::zq_t<Q> b[n * n_bar];

  matrix::mul<n, n, n, n_bar>(a, s, tmp);
  matrix::add<n, n_bar>(tmp, e, b);

  std::memcpy(pkey, seedA, len_seed_A / 8);
  packing::matrix_pack<n, n_bar>(b, pkey + (len_seed_A / 8));
  packing::matrix_pack<n_bar, n>(s_t, skey);
}

// Given a uniformly random seed seedSE, Frodo public key and l -bits message M,
// this routine can be used for encrypting M and computing cipher text,
// following algorithm 10 of FrodoKEM specification.
template<const size_t n,
         const size_t l,
         const size_t m_bar,
         const size_t n_bar,
         const size_t len_seed_A,
         const size_t len_seed_SE,
         const size_t len_χ,
         const uint32_t Q,
         const size_t B>
inline void
encrypt(const uint8_t* const __restrict seedSE, // len_seed_SE -bits
        const uint8_t* const __restrict pkey,
        const uint8_t* const __restrict msg, // l -bits
        uint8_t* const __restrict cipher)
{
  zq::zq_t<Q> a[n * n];
  gen_matrix::gen<len_seed_A, n>(pkey, a);

  uint8_t buf[1 + (len_seed_SE / 8)];
  uint8_t dig[(2 * m_bar * n + m_bar * n_bar) * (len_χ / 8)];

  buf[0] = 0x96;
  std::memcpy(buf + 1, seedSE, len_seed_SE / 8);

  if constexpr (n == 640) {
    shake128::shake128 hasher;

    hasher.hash(buf, sizeof(buf));
    hasher.read(dig, sizeof(dig));
  } else if constexpr ((n == 976) || (n == 1344)) {
    shake256::shake256 hasher;

    hasher.hash(buf, sizeof(buf));
    hasher.read(dig, sizeof(dig));
  }

  zq::zq_t<Q> s_prime[m_bar * n];
  zq::zq_t<Q> e_prime[m_bar * n];
  zq::zq_t<Q> e_dprime[m_bar * n_bar];

  {
    using namespace sampling;

    constexpr size_t off0 = m_bar * n * (len_χ / 8);
    constexpr size_t off1 = off0 + m_bar * n * (len_χ / 8);

    if constexpr (n == 640) {
      const auto Tχ = Frodo640_Tχ;

      sample_matrix<m_bar, n, len_χ, Q, B>(dig, s_prime, Tχ);
      sample_matrix<m_bar, n, len_χ, Q, B>(dig + off0, e_prime, Tχ);
      sample_matrix<m_bar, n_bar, len_χ, Q, B>(dig + off1, e_dprime, Tχ);
    } else if constexpr (n == 976) {
      const auto Tχ = Frodo976_Tχ;

      sample_matrix<m_bar, n, len_χ, Q, B>(dig, s_prime, Tχ);
      sample_matrix<m_bar, n, len_χ, Q, B>(dig + off0, e_prime, Tχ);
      sample_matrix<m_bar, n_bar, len_χ, Q, B>(dig + off1, e_dprime, Tχ);
    } else if constexpr (n == 1344) {
      const auto Tχ = Frodo1344_Tχ;

      sample_matrix<m_bar, n, len_χ, Q, B>(dig, s_prime, Tχ);
      sample_matrix<m_bar, n, len_χ, Q, B>(dig + off0, e_prime, Tχ);
      sample_matrix<m_bar, n_bar, len_χ, Q, B>(dig + off1, e_dprime, Tχ);
    }
  }

  zq::zq_t<Q> tmp0[m_bar * n];
  zq::zq_t<Q> b_prime[m_bar * n];

  matrix::mul<m_bar, n, n, n>(s_prime, a, tmp0);
  matrix::add<m_bar, n>(tmp0, e_prime, b_prime);

  zq::zq_t<Q> b[n * n_bar];
  packing::matrix_unpack<n, n_bar>(pkey + (len_seed_A / 8), b);

  zq::zq_t<Q> tmp1[m_bar * n_bar];
  zq::zq_t<Q> v[m_bar * n_bar];

  matrix::mul<m_bar, n, n, n_bar, Q>(s_prime, b, tmp1);
  matrix::add<m_bar, n_bar>(tmp1, e_dprime, v);

  zq::zq_t<Q> encoded[m_bar * n_bar];
  encoding::matrix_encode<m_bar, n_bar, Q, B>(msg, encoded);

  matrix::add<m_bar, n_bar>(v, encoded, tmp1);

  constexpr size_t cipher_off = (m_bar * n * frodo_utils::log2(Q) + 7) / 8;

  packing::matrix_pack<m_bar, n>(b_prime, cipher);
  packing::matrix_pack<m_bar, n_bar>(tmp1, cipher + cipher_off);
}

// Given a cipher text and Frodo PKE secret key of respective public key, this
// routine can be used for decrypting l -bits message, computing plain text,
// following algorithm 11 of FrodoKEM specification.
template<const size_t n,
         const size_t l,
         const size_t m_bar,
         const size_t n_bar,
         const uint32_t Q,
         const size_t B>
inline void
decrypt(const uint8_t* const __restrict skey,
        const uint8_t* const __restrict cipher,
        uint8_t* const __restrict msg // l -bits
)
{
  zq::zq_t<Q> s_t[n_bar * n];
  zq::zq_t<Q> s[n * n_bar];

  packing::matrix_unpack<n_bar, n>(skey, s_t);
  matrix::transpose<n_bar, n>(s_t, s);

  zq::zq_t<Q> c1[m_bar * n];
  zq::zq_t<Q> c2[m_bar * n_bar];

  constexpr size_t cipher_off = (m_bar * n * frodo_utils::log2(Q) + 7) / 8;

  packing::matrix_unpack<m_bar, n>(cipher, c1);
  packing::matrix_unpack<m_bar, n_bar>(cipher + cipher_off, c2);

  zq::zq_t<Q> tmp[m_bar * n_bar];
  matrix::mul<m_bar, n, n, n_bar, Q>(c1, s, tmp);

  zq::zq_t<Q> m[m_bar * n_bar];
  matrix::sub<m_bar, n_bar>(c2, tmp, m);

  encoding::matrix_decode<m_bar, n_bar, Q, B>(m, msg);
}

}
