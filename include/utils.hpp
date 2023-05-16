#pragma once
#include <bit>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
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
pke_sec_key_len(const size_t n, const size_t n_bar, const uint32_t Q)
{
  const size_t bit_len = n_bar * n * log2(Q);
  const size_t byte_len = (bit_len + 7) / 8;
  return byte_len;
}

// Compile-time computable byte length of Frodo PKE cipher text.
constexpr size_t
pke_cipher_text_len(const size_t n,
                    const size_t m_bar,
                    const size_t n_bar,
                    const uint32_t Q)
{
  const size_t c1 = (m_bar * n * log2(Q) + 7) / 8;
  const size_t c2 = (m_bar * n_bar * log2(Q) + 7) / 8;
  return c1 + c2;
}

// Compile-time computable byte length of Frodo KEM public key.
constexpr size_t
kem_pub_key_len(const size_t n,
                const size_t n_bar,
                const size_t len_seed_A,
                const uint32_t Q)
{
  return pke_pub_key_len(n, n_bar, len_seed_A, Q);
}

// Compile-time computable byte length of Frodo KEM secret key.
constexpr size_t
kem_sec_key_len(const size_t n,
                const size_t n_bar,
                const size_t len_s,
                const size_t len_seed_A,
                const size_t len_pkh,
                const uint32_t Q)
{
  const size_t bit_len = len_s + len_seed_A + 2 * log2(Q) * n * n_bar + len_pkh;
  const size_t byte_len = (bit_len + 7) / 8;
  return byte_len;
}

// Given a bytearray of length N, this function converts it to human readable
// hex string of length N << 1 | N >= 0
inline const std::string
to_hex(const uint8_t* const bytes, const size_t len)
{
  std::stringstream ss;
  ss << std::hex;

  for (size_t i = 0; i < len; i++) {
    ss << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(bytes[i]);
  }

  return ss.str();
}

}
