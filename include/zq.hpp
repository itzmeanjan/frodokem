#pragma once
#include "params.hpp"
#include "utils.hpp"
#include <cstddef>
#include <cstdint>

// Arithmetic over Zq | q ∈ {2^15, 2^16}
namespace zq {

// Wrapper type encapsulating arithmetic over Zq s.t. q is a power of 2 value.
template<const uint32_t Q>
  requires(frodo_params::check_q(Q))
struct zq_t
{
private:
  uint32_t v = 0u;

public:
  // Given an unsigned 32 -bit integer, it constructs an element ∈ Zq
  inline constexpr zq_t(const uint32_t a) { this->v = a % Q; }

  // Addition of two integers modulo Q
  inline constexpr zq_t operator+(const zq_t& rhs) const
  {
    return zq_t((this->v + rhs.v) % Q);
  }

  // Compound addition of two integers modulo Q
  inline constexpr void operator+=(const zq_t& rhs) { *this = *this + rhs; }

  // Negation of an integer modulo Q
  inline constexpr zq_t operator-() const { return zq_t((-this->v) % Q); }

  // Subtraction of one integer from another one, modulo Q
  inline constexpr zq_t operator-(const zq_t& rhs) const
  {
    return *this + (-rhs);
  };

  // Multiply two integers, modulo Q
  inline constexpr zq_t operator*(const zq_t& rhs) const
  {
    return zq_t((this->v * rhs.v) % Q);
  }

  // Given an integer 0 <= k < 2^B, this routine encodes k as an element of Zq
  // s.t. q = 2^D and B <= D, following definition of `ec(k)` function, in
  // section 2.2.1 of FrodoKEM specification.
  template<const size_t B>
  static inline constexpr zq_t encode(const uint32_t k)
  {
    constexpr size_t D = frodo_utils::log2(Q);
    static_assert(B <= D,
                  "# -of bits encoded in each matrix entry must be < 2^B i.e. "
                  "k ∈ [0, 2^B)");

    constexpr uint32_t mask = (1u << B) - 1u;
    constexpr size_t shl = D - B;
    const uint32_t v = (k & mask) << shl;

    return zq_t(v);
  }

  // Given an entry of Zq, this routine extracts its most significant B bits
  // s.t. returned integer v ∈ [0, 2^B).
  template<const size_t B>
  inline constexpr uint32_t decode() const
  {
    constexpr size_t D = frodo_utils::log2(Q);
    static_assert(B <= D,
                  "# -of bits encoded in each matrix entry must be < 2^B i.e. "
                  "k ∈ [0, 2^B)");

    constexpr uint32_t mask = (1u << B) - 1u;
    constexpr size_t shr = D - B;
    const uint32_t v = (this->v >> shr) & mask;

    return v;
  }
};

}
