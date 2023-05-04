#pragma once
#include "zq.hpp"
#include <cstdint>

// Operations on Matrices over Zq
namespace matrix {

// Given a matrix (src) of dimension m x n over Zq, this routine is used for
// computing its transpose matrix (dst) of dimension n x m.
template<const size_t m, const size_t n, const uint32_t Q>
inline void
transpose(const zq::zq_t<Q>* const __restrict src,
          zq::zq_t<Q>* const __restrict dst)
{
  for (size_t i = 0; i < n; i++) {
    for (size_t j = 0; j < m; j++) {
      dst[i * m + j] = src[j * n + i];
    }
  }
}

// Given two matrices (A, B) of same dimension, this routine can be used for
// adding two matrices, resulting into another matrix (C) of same dimension.
template<const size_t m, const size_t n, const uint32_t Q>
inline void
add(const zq::zq_t<Q>* const __restrict matA,
    const zq::zq_t<Q>* const __restrict matB,
    zq::zq_t<Q>* const __restrict matC)
{
  for (size_t i = 0; i < m * n; i++) {
    matC[i] = matA[i] + matB[i];
  }
}

// Given two matrices (A, B) of same dimension, this routine can be used for
// subtracting B from A, resulting into another matrix (C) of same dimension.
template<const size_t m, const size_t n, const uint32_t Q>
inline void
sub(const zq::zq_t<Q>* const __restrict matA,
    const zq::zq_t<Q>* const __restrict matB,
    zq::zq_t<Q>* const __restrict matC)
{
  for (size_t i = 0; i < m * n; i++) {
    matC[i] = matA[i] - matB[i];
  }
}

// Given two matrices A ( of dimension l_m x l_n ) and B ( of dimension r_m x
// r_n ) s.t. l_n == r_m, this routine can be used for multiplying them,
// resulting into another matrix (C) of dimension l_m x r_n.
template<const size_t l_m,
         const size_t l_n,
         const size_t r_m,
         const size_t r_n,
         const uint32_t Q>
inline void
mul(const zq::zq_t<Q>* const __restrict matA,
    const zq::zq_t<Q>* const __restrict matB,
    zq::zq_t<Q>* const __restrict matC)
  requires(l_n == r_m)
{
  for (size_t i = 0; i < l_m; i++) {
    for (size_t j = 0; j < r_n; j++) {
      zq::zq_t<Q> tmp(0);

      for (size_t k = 0; k < l_n; k++) {
        tmp += (matA[i * l_n + k] * matB[k * r_n + j]);
      }
      matC[i * r_n + j] = tmp;
    }
  }
}

// Given a matrix of dimension m x n over Z, this routine is used for
// interpreting it as an matrix over Zq.
template<const size_t m, const size_t n, const uint32_t Q>
inline void
from_Z_to_mod_Q(const int32_t* const __restrict src,
                zq::zq_t<Q>* const __restrict dst)
{
  for (size_t i = 0; i < m * n; i++) {
    dst[i] = zq::zq_t<Q>::from_Z(src[i]);
  }
}

}
