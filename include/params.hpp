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

// Compile-time executable check for ensuring that FrodoKEM key generation
// routine is invoked with proper arguments, as suggested on table A.1, A.2 of
// FrodoKEM specification.
constexpr bool
check_keygen_params(const size_t n, const size_t n̄, const size_t len_sec, const size_t len_SE, const size_t len_A, const size_t B, const size_t D)
{
  return ((n == 640) && (n̄ == 8) && (len_sec == 128) && (len_SE == 128) && (len_A == 128) && (B == 2) && (D == 15)) ||  // eFrodoKEM-640
         ((n == 640) && (n̄ == 8) && (len_sec == 128) && (len_SE == 256) && (len_A == 128) && (B == 2) && (D == 15)) ||  // FrodoKEM-640
         ((n == 976) && (n̄ == 8) && (len_sec == 192) && (len_SE == 192) && (len_A == 128) && (B == 3) && (D == 16)) ||  // eFrodoKEM-976
         ((n == 976) && (n̄ == 8) && (len_sec == 192) && (len_SE == 384) && (len_A == 128) && (B == 3) && (D == 16)) ||  // FrodoKEM-976
         ((n == 1344) && (n̄ == 8) && (len_sec == 256) && (len_SE == 256) && (len_A == 128) && (B == 4) && (D == 16)) || // eFrodoKEM-1344
         ((n == 1344) && (n̄ == 8) && (len_sec == 256) && (len_SE == 512) && (len_A == 128) && (B == 4) && (D == 16))    // FrodoKEM-1344
    ;
}

// Compile-time executable check for ensuring that FrodoKEM encapsulation
// routine is invoked with proper arguments, as suggested on table A.1, A.2 of
// FrodoKEM specification.
constexpr bool
check_encaps_params(const size_t n, const size_t n̄, const size_t len_sec, const size_t len_SE, const size_t len_A, const size_t len_salt, const size_t B, const size_t D)
{
  return ((n == 640) && (n̄ == 8) && (len_sec == 128) && (len_SE == 128) && (len_A == 128) && (len_salt == 0) && (B == 2) && (D == 15)) ||   // eFrodoKEM-640
         ((n == 640) && (n̄ == 8) && (len_sec == 128) && (len_SE == 256) && (len_A == 128) && (len_salt == 256) && (B == 2) && (D == 15)) || // FrodoKEM-640
         ((n == 976) && (n̄ == 8) && (len_sec == 192) && (len_SE == 192) && (len_A == 128) && (len_salt == 0) && (B == 3) && (D == 16)) ||   // eFrodoKEM-976
         ((n == 976) && (n̄ == 8) && (len_sec == 192) && (len_SE == 384) && (len_A == 128) && (len_salt == 384) && (B == 3) && (D == 16)) || // FrodoKEM-976
         ((n == 1344) && (n̄ == 8) && (len_sec == 256) && (len_SE == 256) && (len_A == 128) && (len_salt == 0) && (B == 4) && (D == 16)) ||  // eFrodoKEM-1344
         ((n == 1344) && (n̄ == 8) && (len_sec == 256) && (len_SE == 512) && (len_A == 128) && (len_salt == 512) && (B == 4) && (D == 16))   // FrodoKEM-1344
    ;
}

// Compile-time executable check for ensuring that FrodoKEM decapsulation
// routine is invoked with proper arguments, as suggested on table A.1, A.2 of
// FrodoKEM specification.
constexpr bool
check_decaps_params(const size_t n, const size_t n̄, const size_t len_sec, const size_t len_SE, const size_t len_A, const size_t len_salt, const size_t B, const size_t D)
{
  return check_encaps_params(n, n̄, len_sec, len_SE, len_A, len_salt, B, D);
}

}
