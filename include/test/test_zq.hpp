#pragma once
#include "zq.hpp"
#include <cassert>

// Test functional correctness of FrodoKEM along with its components.
namespace test_frodo {

// Test if
//
// - encoding bit string to Zq element
// - decoding Zq element to bit string
//
// works as expected.
//
// dc(ec(k)) = k ∀ k ∈ [0, 2^B) must hold !
// See section 2.2.1 of FrodoKEM specification
// https://frodokem.org/files/FrodoKEM-specification-20210604.pdf.
template<const size_t D, const size_t B>
void
test_zq_encode_decode()
{
  constexpr uint16_t min_v = 0u;
  constexpr uint16_t max_v = 1u << B;

  for (uint16_t v = min_v; v < max_v; v++) {
    const auto enc = zq::zq_t<D>::template encode<B>(v);
    const auto dec = enc.template decode<B>();

    assert(v == dec);
  }
}

// Ensure that this implementation satisfies lemma 2.18 of FrodoKEM
// specification (
// https://frodokem.org/files/FrodoKEM-specification-20210604.pdf ), which
// states the bounds on the size of errors that can be handled by the decoding
// algorithm.
template<const size_t D, const size_t B>
void
test_lemma_2_18()
{
  // k ∈ [0, 2^B)
  constexpr uint16_t min_k = 0;
  constexpr uint16_t max_k = (1u << B) - 1;

  // e ∈ [-q/ 2^(B+1), q/ 2^(B+1))
  constexpr uint32_t Q = 1u << D;
  constexpr int16_t min_e = -static_cast<int16_t>(Q / (1u << (B + 1)));
  constexpr int16_t max_e = static_cast<int16_t>(Q / (1u << (B + 1))) - 1u;

  for (uint16_t k = min_k; k <= max_k; k++) {
    // = ec(k)
    const auto v = zq::zq_t<D>::template encode<B>(k);

    for (int16_t e = min_e; e <= max_e; e++) {
      // = ec(k) + e
      const auto u = v + zq::zq_t<D>(static_cast<uint16_t>(e));
      // = dc(ec(k) + e)
      const auto t = u.template decode<B>();

      assert(k == t);
    }
  }
}

}
