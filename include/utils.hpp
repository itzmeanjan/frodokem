#pragma once
#include <array>
#include <bit>
#include <cassert>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <span>
#include <sstream>
#include <string_view>
#include <type_traits>

// Some utility functions, required for FrodoKEM
namespace frodo_utils {

// Compile-time computable byte length of Frodo KEM public key, following
// description in section 8 of FrodoKEM specification.
constexpr size_t
kem_pub_key_len(const size_t n, const size_t n̄, const size_t len_A, const size_t D)
{
  return (len_A + D * n * n̄) / 8;
}

// Compile-time computable byte length of Frodo KEM secret key, following
// description in section 8 of FrodoKEM specification.
constexpr size_t
kem_sec_key_len(const size_t n, const size_t n̄, const size_t len_sec, const size_t len_A, const size_t D)
{
  return (2 * len_sec + len_A + D * n * n̄ + 16 * n * n̄) / 8;
}

// Compile-time computable byte length of Frodo KEM cipher text, following
// description in section 8 of FrodoKEM specification.
constexpr size_t
kem_cipher_text_len(const size_t n, const size_t n̄, const size_t len_salt, const size_t D)
{
  return (D * n * n̄ + D * n̄ * n̄ + len_salt) / 8;
}

// Given a bytearray of length N, this function converts it to human readable
// hex string of length N << 1 | N >= 0
inline const std::string
to_hex(std::span<uint8_t> bytes)
{
  std::stringstream ss;
  ss << std::hex;

  for (size_t i = 0; i < bytes.size(); i++) {
    ss << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(bytes[i]);
  }

  return ss.str();
}

// Given a hex encoded string of length 2*L, this routine can be used for
// parsing it as a byte array of length L.
template<size_t L>
inline std::array<uint8_t, L>
from_hex(std::string_view bytes)
{
  const size_t blen = bytes.length();

  assert(blen % 2 == 0);
  assert(blen / 2 == L);

  std::array<uint8_t, L> res{};

  for (size_t i = 0; i < L; i++) {
    const size_t off = i * 2;

    uint8_t byte = 0;
    auto sstr = bytes.substr(off, 2);
    std::from_chars(sstr.data(), sstr.data() + 2, byte, 16);

    res[i] = byte;
  }

  return res;
}

}
