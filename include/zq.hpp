#pragma once
#include "params.hpp"
#include "prng.hpp"
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
  inline constexpr zq_t(const uint32_t a = 0u) { this->v = a % Q; }

  // Given an element v ∈ [-q/ 2^(B+1), q/ 2^(B+1)) s.t. q = 2^D, B <= D, this
  // routine is used for deriving an element ∈ [0, q/ 2^B).
  template<const size_t B>
  static inline constexpr zq_t from_Z(const int32_t v)
  {
    constexpr size_t D = frodo_utils::log2(Q);
    static_assert(B <= D, "v must ∈ [-q/ 2^(B+1), q/ 2^(B+1))");

    constexpr uint32_t wrap_at = 1u << (D - B);
    const bool flg = v < 0;
    const int32_t wrapped = static_cast<int32_t>(wrap_at) * flg + v;

    return zq_t(static_cast<uint32_t>(wrapped));
  }

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

  // Check equality of two Zq elements
  inline constexpr bool operator==(const zq_t& rhs) const
  {
    return this->v == rhs.v;
  }

  // Check inequality of two Zq elements
  inline constexpr bool operator!=(const zq_t& rhs) const
  {
    return !(*this == rhs);
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

  // Get the raw value behind Zq wrapper type.
  inline constexpr uint32_t get_value() const { return this->v; }

  // Reads four random bytes from PRNG and computes a random element ∈ Zq.
  static inline zq_t random_value(prng::prng_t& prng)
  {
    uint32_t res = 0;
    prng.read(reinterpret_cast<uint8_t*>(&res), sizeof(res));

    return zq_t(res);
  }
};

}
