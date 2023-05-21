#pragma once
#include "params.hpp"
#include "prng.hpp"
#include "utils.hpp"
#include <cstddef>
#include <cstdint>

// Arithmetic over Zq | q = 2^D and D <= 16
namespace zq {

// Wrapper type encapsulating arithmetic over Zq i.e. mod q (= 2^D).
template<const size_t D>
  requires(frodo_params::check_d(D))
struct zq_t
{
private:
  uint16_t v = 0u;

public:
  // Default constructor returning Zq, with value 0.
  inline constexpr zq_t() = default;

  // Given an unsigned 16 -bit integer, it constructs an element ∈ Zq
  inline constexpr zq_t(const uint16_t _v) { this->v = _v; }

  // Addition of two integers modulo Q
  inline constexpr zq_t operator+(const zq_t& rhs) const
  {
    return zq_t(this->v + rhs.v);
  }

  // Compound addition of two integers modulo Q
  inline constexpr void operator+=(const zq_t& rhs) { *this = *this + rhs; }

  // Negation of an integer modulo Q
  inline constexpr zq_t operator-() const { return zq_t(-this->v); }

  // Subtraction of one integer from another one, modulo Q
  inline constexpr zq_t operator-(const zq_t& rhs) const
  {
    return *this + (-rhs);
  };

  // Multiply two integers, modulo Q
  inline constexpr zq_t operator*(const zq_t& rhs) const
  {
    return zq_t(this->v * rhs.v);
  }

  // Check equality between canonical form of two Zq elements
  inline constexpr bool operator==(const zq_t& rhs) const
  {
    return this->to_canonical() == rhs.to_canonical();
  }

  // Check inequality between canonical form of two Zq elements
  inline constexpr bool operator!=(const zq_t& rhs) const
  {
    return !(*this == rhs);
  }

  // Given an integer 0 <= k < 2^B, this routine encodes k as an element of Zq
  // s.t. q = 2^D and B <= D, following definition of `ec(k)` function, in
  // section 2.2.1 of FrodoKEM specification.
  template<const size_t B>
  static inline constexpr zq_t encode(const uint16_t k)
    requires(B <= D)
  {
    constexpr uint16_t mask = (1u << B) - 1u;
    constexpr size_t shl = D - B;

    const uint16_t v = (k & mask) << shl;
    return zq_t(v);
  }

  // Given an entry of Zq, this routine extracts its most significant B bits
  // s.t. returned integer v ∈ [0, 2^B), collecting inspiration from
  // https://github.com/microsoft/PQCrypto-LWEKE/blob/d7037ccb/python3/frodokem.py#L335.
  template<const size_t B>
  inline constexpr uint16_t decode() const
    requires(B <= D)
  {
    constexpr uint32_t mask = (1u << B) - 1u;

    const uint32_t t = (static_cast<uint32_t>(this->v) << B) + (1u << (D - 1));
    const uint32_t v = (t >> D) & mask;
    return static_cast<uint16_t>(v);
  }

  // Get the canonical value ( i.e. reduced by Q ) behind Zq wrapper type.
  inline constexpr uint16_t to_canonical() const
  {
    constexpr uint16_t mask = (1u << D) - 1u;
    return this->v & mask;
  }

  // Get the raw 16 -bit value behind Zq wrapper type.
  inline constexpr uint16_t to_raw() const { return this->v; }

  // Reads two random bytes from PRNG and computes a random element ∈ Zq.
  static inline zq_t random_value(prng::prng_t& prng)
  {
    uint16_t res = 0;
    // note, no specific endianness is preferred here !
    prng.read(reinterpret_cast<uint8_t*>(&res), sizeof(res));

    return zq_t(res);
  }
};

}
