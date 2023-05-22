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

// Compile-time executable check for ensuring that FrodoKEM key generation
// routine is invoked with proper arguments, as suggested on table 4 of FrodoKEM
// specification.
constexpr bool
check_frodo_keygen_params(const size_t n,
                          const size_t n_bar,
                          const size_t len_seed_A,
                          const size_t len_seed_SE,
                          const size_t len_s,
                          const size_t len_z,
                          const size_t len_pkh,
                          const size_t len_χ,
                          const size_t D,
                          const size_t B)
{
  return ((n == 640) && (n_bar == 8) && (len_seed_A == 128) &&
          (len_seed_SE == 128) && (len_s == 128) && (len_z == 128) &&
          (len_pkh == 128) && (len_χ == 16) && (D == 15) && (B == 2)) ||
         ((n == 976) && (n_bar == 8) && (len_seed_A == 128) &&
          (len_seed_SE == 192) && (len_s == 192) && (len_z == 128) &&
          (len_pkh == 192) && (len_χ == 16) && (D == 16) && (B == 3)) ||
         ((n == 1344) && (n_bar == 8) && (len_seed_A == 128) &&
          (len_seed_SE == 256) && (len_s == 256) && (len_z == 128) &&
          (len_pkh == 256) && (len_χ == 16) && (D == 16) && (B == 4));
}

// Compile-time executable check for ensuring that FrodoKEM encapsulation
// routine is invoked with proper arguments, as suggested on table 4 of FrodoKEM
// specification.
constexpr bool
check_frodo_encaps_params(const size_t n,
                          const size_t m_bar,
                          const size_t n_bar,
                          const size_t len_seed_A,
                          const size_t len_seed_SE,
                          const size_t len_ss,
                          const size_t len_k,
                          const size_t len_μ,
                          const size_t len_pkh,
                          const size_t len_χ,
                          const size_t D,
                          const size_t B)
{
  return ((n == 640) && (m_bar == 8) && (m_bar == n_bar) &&
          (len_seed_A == 128) && (len_seed_SE == 128) && (len_ss == 128) &&
          (len_k == 128) && (len_μ == 128) && (len_pkh == 128) &&
          (len_χ == 16) && (D == 15) && (B == 2)) ||
         ((n == 976) && (m_bar == 8) && (m_bar == n_bar) &&
          (len_seed_A == 128) && (len_seed_SE == 192) && (len_ss == 192) &&
          (len_k == 192) && (len_μ == 192) && (len_pkh == 192) &&
          (len_χ == 16) && (D == 16) && (B == 3)) ||
         ((n == 1344) && (m_bar == 8) && (m_bar == n_bar) &&
          (len_seed_A == 128) && (len_seed_SE == 256) && (len_ss == 256) &&
          (len_k == 256) && (len_μ == 256) && (len_pkh == 256) &&
          (len_χ == 16) && (D == 16) && (B == 4));
}

// Compile-time executable check for ensuring that FrodoKEM decapsulation
// routine is invoked with proper arguments, as suggested on table 4 of FrodoKEM
// specification.
constexpr bool
check_frodo_decaps_params(const size_t n,
                          const size_t m_bar,
                          const size_t n_bar,
                          const size_t len_seed_A,
                          const size_t len_seed_SE,
                          const size_t len_s,
                          const size_t len_ss,
                          const size_t len_k,
                          const size_t len_μ,
                          const size_t len_pkh,
                          const size_t len_χ,
                          const size_t D,
                          const size_t B)
{
  return ((n == 640) && (m_bar == 8) && (m_bar == n_bar) &&
          (len_seed_A == 128) && (len_seed_SE == 128) && (len_s == 128) &&
          (len_ss == 128) && (len_k == 128) && (len_μ == 128) &&
          (len_pkh == 128) && (len_χ == 16) && (D == 15) && (B == 2)) ||
         ((n == 976) && (m_bar == 8) && (m_bar == n_bar) &&
          (len_seed_A == 128) && (len_seed_SE == 192) && (len_s == 192) &&
          (len_ss == 192) && (len_k == 192) && (len_μ == 192) &&
          (len_pkh == 192) && (len_χ == 16) && (D == 16) && (B == 3)) ||
         ((n == 1344) && (m_bar == 8) && (m_bar == n_bar) &&
          (len_seed_A == 128) && (len_seed_SE == 256) && (len_s == 256) &&
          (len_ss == 256) && (len_k == 256) && (len_μ == 256) &&
          (len_pkh == 256) && (len_χ == 16) && (D == 16) && (B == 4));
}

}
