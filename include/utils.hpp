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

// Compile-time computable byte length of Frodo PKE public key.
constexpr size_t
pke_pub_key_len(const size_t n,
                const size_t n_bar,
                const size_t len_seed_A,
                const uint32_t Q)
{
  const size_t bit_len = len_seed_A +           // bit length of seed
                         (n * n_bar * log2(Q)); // matrix B packed as bitstring
  const size_t byte_len = (bit_len + 7) / 8;
  return byte_len;
}

// Compile-time computable byte length of Frodo PKE secret key.
constexpr size_t
pke_sec_key_len(const size_t n_bar, const size_t n, const uint32_t Q)
{
  const size_t bit_len = n_bar * n * log2(Q);
  const size_t byte_len = (bit_len + 7) / 8;
  return byte_len;
}

}
