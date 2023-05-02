#pragma once
#include <cstddef>
#include <cstdint>

// Compile-time executable checks for FrodoKEM Parameters.
namespace frodo_params {

// Compile-time executable check for ensuring that FrodoKEM's parameter i.e.
// integer modulus Q has correct value.
constexpr bool
check_q(const uint32_t q)
{
  return ((q & (q - 1)) == 0)  // q must be power of 2
         && (q <= (1u << 16)); // and it must be <= 2^16
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

}
