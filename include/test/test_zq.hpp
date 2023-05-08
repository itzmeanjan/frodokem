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
// See section 2.2.1 of FrodoKEM specification.
template<const uint32_t Q, const size_t B>
void
test_zq_encode_decode()
{
  constexpr size_t min_v = 0u;
  constexpr size_t max_v = 1u << B;

  for (uint32_t v = min_v; v < max_v; v++) {
    const auto enc = zq::zq_t<Q>::template encode<B>(v);
    const auto dec = enc.template decode<B>();

    assert(v == dec);
  }
}

// Ensure that this implementation satisfies lemma 2.18 of FrodoKEM
// specification, which states the bounds on the size of errors that can be
// handled by the decoding algorithm.
template<const uint32_t Q, const size_t B>
void
test_lemma_2_18()
{
  // k ∈ [0, 2^B)
  constexpr uint32_t min_k = 0;
  constexpr uint32_t max_k = (1u << B) - 1;

  // e ∈ [-q/ 2^(B+1), q/ 2^(B+1))
  constexpr int32_t min_e = -static_cast<int32_t>(Q / (1 << (B + 1)));
  constexpr int32_t max_e = static_cast<int32_t>(Q / (1 << (B + 1))) - 1;

  for (uint32_t k = min_k; k <= max_k; k++) {
    // = ec(k)
    const auto v = zq::zq_t<Q>::template encode<B>(k);

    for (int32_t e = min_e; e <= max_e; e++) {
      // = ec(k) + e
      const auto u = v + zq::zq_t<Q>::template from_Z<B>(e);
      // = dc(ec(k) + e)
      const auto t = u.template decode<B>();

      assert(k == t);
    }
  }
}

}
