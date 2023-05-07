#pragma once
#include "matrix.hpp"
#include "prng.hpp"
#include "zq.hpp"
#include <cassert>

// Test functional correctness of FrodoKEM along with its components.
namespace test_frodo {

// Test if, given a matrix of dimension m x n, this it can correctly be
// transposed into a matrix of dimension n x m.
template<const size_t m, const size_t n, const uint32_t Q>
void
test_matrix_transpose()
{
  constexpr size_t mat_len = sizeof(zq::zq_t<Q>) * m * n;

  auto mat_a = static_cast<zq::zq_t<Q>*>(std::malloc(mat_len)); // m x n
  auto mat_b = static_cast<zq::zq_t<Q>*>(std::malloc(mat_len)); // n x m
  auto mat_c = static_cast<zq::zq_t<Q>*>(std::malloc(mat_len)); // m x n

  // pseudo randomness, for generating random matrix
  prng::prng_t prng;

  for (size_t i = 0; i < (m * n); i++) {
    mat_a[i] = zq::zq_t<Q>::random_value(prng);
  }

  matrix::transpose<m, n, Q>(mat_a, mat_b);
  matrix::transpose<n, m, Q>(mat_b, mat_c);

  for (size_t i = 0; i < (m * n); i++) {
    assert(mat_a[i] == mat_c[i]);
  }

  std::free(mat_a);
  std::free(mat_b);
  std::free(mat_c);
}

}
