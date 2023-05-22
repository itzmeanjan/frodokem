#pragma once
#include "matrix.hpp"
#include "prng.hpp"
#include "zq.hpp"
#include <cassert>

// Test functional correctness of FrodoKEM along with its components.
namespace test_frodo {

// Test if, given a matrix of dimension m x n, it can correctly be transposed
// into a matrix of dimension n x m.
template<const size_t m, const size_t n, const size_t D>
void
test_matrix_transpose()
{
  prng::prng_t prng;

  auto mat_a = matrix::matrix<m, n, D>::random(prng);
  auto mat_b = mat_a.transpose();
  auto mat_c = mat_b.transpose();

  assert(mat_a == mat_c);
}

// Test if, addition and subtraction of two matrices ( of same dimension ) is
// implemented correctly.
template<const size_t m, const size_t n, const size_t D>
void
test_matrix_add_sub()
{
  prng::prng_t prng;

  auto mat_a = matrix::matrix<m, n, D>::random(prng);
  auto mat_b = matrix::matrix<m, n, D>::random(prng);

  auto mat_c = mat_a + mat_b;
  auto mat_d = mat_c - mat_b;

  assert(mat_a == mat_d);
}

}
