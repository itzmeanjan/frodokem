#pragma once
#include "encoding.hpp"
#include "prng.hpp"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstring>

// Test functional correctness of FrodoKEM along with its components.
namespace test_frodo {

// Test if
//
// - encoding bit string of length m x n x B to matrix of dimension m x n
// - decoding matrix of dimension m x n to bit string of length m x n x B
//
// works as expected.
//
// In other words, following test ensures that implementation of algorithm 1, 2
// ( of FrodoKEM specification ) is correct for various parameters.
template<const size_t m, const size_t n, const size_t D, const size_t B>
void
test_matrix_encode_decode()
{
  constexpr size_t bit_len = m * n * B;
  constexpr size_t byte_len = (bit_len + 7) / 8;

  std::array<uint8_t, byte_len> org_bytes{};
  std::array<uint8_t, byte_len> fin_bytes{};

  prng::prng_t prng;
  prng.read(org_bytes);

  auto encoded = encoding::encode<m, n, D, B>(org_bytes);
  encoding::decode<m, n, D, B>(encoded, fin_bytes);

  assert(std::ranges::equal(org_bytes, fin_bytes));
}

}
