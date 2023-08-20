#include "matrix.hpp"
#include "packing.hpp"
#include "prng.hpp"
#include "utils.hpp"
#include "zq.hpp"
#include <array>
#include <gtest/gtest.h>

// Test if
//
// - packing a n1 x n2 matrix over Zq into a bit string of n1 x n2 x D -bits
// - unpacking a bit string of n1 x n2 x D -bits into a n1 x n2 matrix
//
// works as expected.
//
// In other words, following test ensures that algorithm description, in
// section 7.4 of FrodoKEM specification, is correctly implemented.
template<const size_t n1, const size_t n2, const size_t D>
void
test_matrix_pack_unpack()
{
  constexpr size_t bit_len = n1 * n2 * D;
  constexpr size_t byte_len = (bit_len + 7) / 8;

  prng::prng_t prng;

  auto mat = matrix::matrix<n1, n2, D>::random(prng);
  std::array<uint8_t, byte_len> packed{};

  packing::pack<n1, n2, D>(mat, packed);
  auto unpacked = packing::unpack<n1, n2, D>(packed);

  EXPECT_EQ(mat, unpacked);
}

TEST(FrodoKEM, MatrixPackUnpack)
{
  test_matrix_pack_unpack<640, 8, 15>();
  test_matrix_pack_unpack<8, 640, 15>();
  test_matrix_pack_unpack<976, 8, 16>();
  test_matrix_pack_unpack<8, 976, 16>();
  test_matrix_pack_unpack<1344, 8, 16>();
  test_matrix_pack_unpack<8, 1344, 16>();
  test_matrix_pack_unpack<8, 8, 15>();
  test_matrix_pack_unpack<8, 8, 16>();
}
