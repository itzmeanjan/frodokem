#pragma once
#include "encoding.hpp"
#include "prng.hpp"
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
template<const size_t m, const size_t n, const uint32_t Q, const size_t B>
void
test_matrix_encode_decode()
{
  constexpr size_t bit_len = m * n * B;
  constexpr size_t byte_len = (bit_len + 7) / 8;
  constexpr size_t mat_len = sizeof(zq::zq_t<Q>) * m * n;

  auto org_enc = static_cast<uint8_t*>(std::malloc(byte_len));
  auto decoded = static_cast<zq::zq_t<Q>*>(std::malloc(mat_len));
  auto fin_enc = static_cast<uint8_t*>(std::malloc(byte_len));

  prng::prng_t prng;
  prng.read(org_enc, byte_len);
  std::memset(fin_enc, 0, byte_len);

  encoding::matrix_encode<m, n, Q, B>(org_enc, decoded);
  encoding::matrix_decode<m, n, Q, B>(decoded, fin_enc);

  for (size_t i = 0; i < byte_len; i++) {
    assert(org_enc[i] == fin_enc[i]);
  }

  std::free(org_enc);
  std::free(decoded);
  std::free(fin_enc);
}

}
