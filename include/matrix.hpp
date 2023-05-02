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

}
