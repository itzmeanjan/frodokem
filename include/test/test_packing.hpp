#pragma once
#include "packing.hpp"
#include "prng.hpp"
#include "utils.hpp"
#include "zq.hpp"
#include <cassert>

// Test functional correctness of FrodoKEM along with its components.
namespace test_frodo {

// Test if
//
// - packing a n1 x n2 matrix over Zq into a bit string of n1 x n2 x D -bits
// - unpacking a bit string of n1 x n2 x D -bits into a n1 x n2 matrix
//
// works as expected.
//
// In other words, following test ensures that algorithm 3, 4 ( of FrodoKEM
// specification ) is correctly implemented.
template<const size_t n1, const size_t n2, const uint32_t Q>
void
test_matrix_pack_unpack()
{
  constexpr size_t D = frodo_utils::log2(Q);
  constexpr size_t bit_len = n1 * n2 * D;
  constexpr size_t byte_len = (bit_len + 7) / 8;
  constexpr size_t mat_len = sizeof(zq::zq_t<Q>) * n1 * n2;

  auto mat = static_cast<zq::zq_t<Q>*>(std::malloc(mat_len));
  auto packed = static_cast<uint8_t*>(std::malloc(byte_len));
  auto unpacked = static_cast<zq::zq_t<Q>*>(std::malloc(mat_len));

  prng::prng_t prng;

  for (size_t i = 0; i < (n1 * n2); i++) {
    mat[i] = zq::zq_t<Q>::random_value(prng);
  }
  std::memset(packed, 0, byte_len);

  packing::matrix_pack<n1, n2, Q>(mat, packed);
  packing::matrix_unpack<n1, n2, Q>(packed, unpacked);

  for (size_t i = 0; i < (n1 * n2); i++) {
    assert(mat[i] == unpacked[i]);
  }

  std::free(mat);
  std::free(packed);
  std::free(unpacked);
}

}
