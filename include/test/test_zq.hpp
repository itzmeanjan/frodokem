#pragma once
#include "zq.hpp"
#include <cassert>
#include <cstdint>
#include <iostream>

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

}
