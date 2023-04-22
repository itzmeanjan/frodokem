#pragma once
#include "params.hpp"
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
  inline constexpr zq_t(const uint32_t a)
    : v(a % Q)
  {
  }

  // Addition of two integers modulo Q
  inline constexpr zq_t operator+(const zq_t& rhs) const
  {
    return zq_t((this->v + rhs.v) % Q);
  }

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
};

}
