#pragma once
#include "gen_matrix.hpp"
#include "matrix.hpp"
#include "packing.hpp"
#include "sampling.hpp"
#include "shake128.hpp"
#include "shake256.hpp"
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
         const uint32_t Q>
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

  int32_t s_t[n_bar * n];
  int32_t e[n * n_bar];

  constexpr size_t off = n * n_bar * (len_χ / 8);

  {
    using namespace sampling;

    if constexpr (n == 640) {
      sample_matrix<n_bar, n, len_χ>(dig, s_t, Frodo640_Tχ);
      sample_matrix<n, n_bar, len_χ>(dig + off, e, Frodo640_Tχ);
    } else if constexpr (n == 976) {
      sample_matrix<n_bar, n, len_χ>(dig, s_t, Frodo976_Tχ);
      sample_matrix<n, n_bar, len_χ>(dig + off, e, Frodo976_Tχ);
    } else if constexpr (n == 1344) {
      sample_matrix<n_bar, n, len_χ>(dig, s_t, Frodo1344_Tχ);
      sample_matrix<n, n_bar, len_χ>(dig + off, e, Frodo1344_Tχ);
    }
  }

  zq::zq_t<Q> s_t_[n_bar * n];
  zq::zq_t<Q> e_[n * n_bar];

  matrix::from_Z_to_mod_Q<n_bar, n>(s_t, s_t_);
  matrix::from_Z_to_mod_Q<n, n_bar>(e, e_);

  zq::zq_t<Q> s[n * n_bar];
  matrix::transpose<n_bar, n>(s_t_, s);

  zq::zq_t<Q> tmp[n * n_bar];
  zq::zq_t<Q> b[n * n_bar];

  matrix::mul<n, n, n, n_bar>(a, s, tmp);
  matrix::add<n, n_bar>(tmp, e_, b);

  std::memcpy(pkey, seedA, len_seed_A / 8);
  packing::matrix_pack<n, n_bar>(b, pkey + (len_seed_A / 8));
  packing::matrix_pack<n_bar, n>(s_t_, skey);
}

}
