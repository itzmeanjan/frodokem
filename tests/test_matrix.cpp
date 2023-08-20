#include "matrix.hpp"
#include "prng.hpp"
#include "zq.hpp"
#include <gtest/gtest.h>

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

  EXPECT_EQ(mat_a, mat_c);
}

TEST(FrodoKEM, MatrixTranspose)
{
  test_matrix_transpose<8, 640, 15>();
  test_matrix_transpose<8, 976, 16>();
  test_matrix_transpose<8, 1344, 16>();
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

  EXPECT_EQ(mat_a, mat_d);
}

TEST(FrodoKEM, MatrixAddSub)
{
  test_matrix_add_sub<8, 640, 15>();
  test_matrix_add_sub<8, 976, 16>();
  test_matrix_add_sub<8, 1344, 16>();
  test_matrix_add_sub<8, 8, 15>();
  test_matrix_add_sub<8, 8, 16>();
}
