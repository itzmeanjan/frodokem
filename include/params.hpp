#pragma once
#include <cstddef>
#include <cstdint>

// Compile-time executable checks for FrodoKEM Parameters.
namespace frodo_params {

// Compile-time executable check for ensuring that FrodoKEM's parameter i.e.
// integer modulus Q has correct value.
constexpr bool
check_q(const size_t q)
{
  return ((q & (q - 1)) == 0)   // q must be power of 2
         && (q <= (1ul << 16)); // and it must be <= 2^16
}

}
