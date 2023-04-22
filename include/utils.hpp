#pragma once
#include <bit>
#include <cstddef>
#include <cstdint>
#include <type_traits>

// Some utility functions, required for FrodoKEM
namespace frodo_utils {

// Given an unsigned integer of bitwidth b ∈ {8, 16, 32, 64}, this routine can
// be used for computing logarithm base 2 for power of 2 value s.t. v ∈ [1, 2^b)
template<typename T>
  requires(std::is_unsigned_v<T>)
inline constexpr size_t log2(const T v)
{
  return std::countr_zero(v);
}

}
