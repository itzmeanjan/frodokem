#pragma once
#include <cstddef>
#include <cstdint>

// Compile-time executable checks for FrodoKEM Parameters.
namespace frodo_params {

// Compile-time executable check for ensuring that FrodoKEM's parameter i.e.
// integer modulus Q ( = 2^D ) has correct value.
constexpr bool
check_d(const size_t d)
{
  return d <= 16;
}

// Compile-time executable check for ensuring that FrodoKEM's parameter B only
// takes arguments suggested on table 4 of FrodoKEM specification.
constexpr bool
check_b(const size_t b)
{
  return (b == 2) || (b == 3) || (b == 4);
}

// Compile-time executable check for ensuring that FrodoKEM's parameter len_χ
// only takes arguments suggested on table 4 of FrodoKEM specification.
constexpr bool
check_len_χ(const size_t len_χ)
{
  return len_χ == 16;
}

// Compile-time executable check for ensuring that Frodo PKE's key generation
// routine is invoked with proper arguments, as suggested on table 4 of FrodoKEM
// specification.
constexpr bool
check_frodo_pke_keygen_params(const size_t n,
                              const size_t n_bar,
                              const size_t len_seed_A,
                              const size_t len_seed_SE,
                              const size_t len_χ,
                              const uint32_t Q,
                              const size_t B)
{
  return ((n == 640) && (n_bar == 8) && (len_seed_A == 128) &&
          (len_seed_SE == 128) && (len_χ == 16) && (Q == (1u << 15)) &&
          (B == 2)) ||
         ((n == 976) && (n_bar == 8) && (len_seed_A == 128) &&
          (len_seed_SE == 192) && (len_χ == 16) && (Q == (1u << 16)) &&
          (B == 3)) ||
         ((n == 1344) && (n_bar == 8) && (len_seed_A == 128) &&
          (len_seed_SE == 256) && (len_χ == 16) && (Q == (1u << 16)) &&
          (B == 4));
}

// Compile-time executable check for ensuring that Frodo PKE's encryption
// routine is invoked with proper arguments, as suggested on table 4 of FrodoKEM
// specification.
constexpr bool
check_frodo_pke_encrypt_params(const size_t n,
                               const size_t l,
                               const size_t m_bar,
                               const size_t n_bar,
                               const size_t len_seed_A,
                               const size_t len_seed_SE,
                               const size_t len_χ,
                               const uint32_t Q,
                               const size_t B)
{
  return ((n == 640) && (l == 128) && (m_bar == 8) && (m_bar == n_bar) &&
          (len_seed_A == 128) && (len_seed_SE == 128) && (len_χ == 16) &&
          (Q == (1u << 15)) && (B == 2)) ||
         ((n == 976) && (l == 192) && (m_bar == 8) && (m_bar == n_bar) &&
          (len_seed_A == 128) && (len_seed_SE == 192) && (len_χ == 16) &&
          (Q == (1u << 16)) && (B == 3)) ||
         ((n == 1344) && (l == 256) && (m_bar == 8) && (m_bar == n_bar) &&
          (len_seed_A == 128) && (len_seed_SE == 256) && (len_χ == 16) &&
          (Q == (1u << 16)) && (B == 4));
}

// Compile-time executable check for ensuring that Frodo PKE's decryption
// routine is invoked with proper arguments, as suggested on table 4 of FrodoKEM
// specification.
constexpr bool
check_frodo_pke_decrypt_params(const size_t n,
                               const size_t l,
                               const size_t m_bar,
                               const size_t n_bar,
                               const uint32_t Q,
                               const size_t B)
{
  return ((n == 640) && (l == 128) && (m_bar == 8) && (m_bar == n_bar) &&
          (Q == (1u << 15)) && (B == 2)) ||
         ((n == 976) && (l == 192) && (m_bar == 8) && (m_bar == n_bar) &&
          (Q == (1u << 16)) && (B == 3)) ||
         ((n == 1344) && (l == 256) && (m_bar == 8) && (m_bar == n_bar) &&
          (Q == (1u << 16)) && (B == 4));
  ;
}

}
