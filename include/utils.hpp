#pragma once
#include <array>
#include <bit>
#include <cassert>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string_view>
#include <type_traits>

// Some utility functions, required for FrodoKEM
namespace frodo_utils {

// Compile-time computable byte length of Frodo KEM public key.
constexpr size_t
kem_pub_key_len(const size_t n,
                const size_t n_bar,
                const size_t len_seed_A,
                const size_t D)
{
  const size_t bit_len = len_seed_A +     // bit length of seed
                         (n * n_bar * D); // matrix B packed as bitstring
  const size_t byte_len = (bit_len + 7) / 8;
  return byte_len;
}

// Compile-time computable byte length of Frodo KEM secret key.
constexpr size_t
kem_sec_key_len(const size_t n,
                const size_t n_bar,
                const size_t len_s,
                const size_t len_seed_A,
                const size_t len_pkh,
                const size_t D)
{
  const size_t t0 = len_s / 8;
  const size_t t1 = kem_pub_key_len(n, n_bar, len_seed_A, D);
  const size_t t2 = n * n_bar * 2;
  const size_t t3 = len_pkh / 8;

  return t0 + t1 + t2 + t3;
}

// Compile-time computable byte length of Frodo KEM cipher text.
constexpr size_t
kem_cipher_text_len(const size_t n,
                    const size_t m_bar,
                    const size_t n_bar,
                    const size_t D)
{
  const size_t c1 = (m_bar * n * D + 7) / 8;
  const size_t c2 = (m_bar * n_bar * D + 7) / 8;
  return c1 + c2;
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

// Given a hex encoded string of length 2*L, this routine can be used for
// parsing it as a byte array of length L.
template<const size_t L>
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
