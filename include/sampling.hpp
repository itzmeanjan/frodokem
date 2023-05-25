#pragma once
#include "matrix.hpp"
#include "params.hpp"
#include "subtle.hpp"
#include "zq.hpp"
#include <array>
#include <numeric>
#include <span>

// Sampling from the error distribution
namespace sampling {

// Discrete, symmetric error distribution over Z, centered at 0, for
// {e}Frodo-640, as given on table A.3 of FrodoKEM specification.
constexpr std::array<uint16_t, 13> Frodo640_χ = { 9288, 8720, 7216, 5264, 3384,
                                                  1918, 958,  422,  164,  56,
                                                  17,   4,    1 };

// Discrete, symmetric error distribution over Z, centered at 0, for
// {e}Frodo-976, as given on table A.3 of FrodoKEM specification.
constexpr std::array<uint16_t, 11> Frodo976_χ = { 11278, 10277, 7774, 4882,
                                                  2545,  1101,  396,  118,
                                                  29,    6,     1 };

// Discrete, symmetric error distribution over Z, centered at 0, for
// {e}Frodo-1344, as given on table A.3 of FrodoKEM specification.
constexpr std::array<uint16_t, 7> Frodo1344_χ = { 18286, 14320, 6876, 2023,
                                                  364,   40,    2 };

// Compile-time compute a zero-centerd CDF, suitable for sampling using a
// uniform random value, following equations provided in section 2.2.4 of
// FrodoKEM specification
// https://frodokem.org/files/FrodoKEM-specification-20210604.pdf.
//
// You can find reference implementation @
// https://github.com/microsoft/PQCrypto-LWEKE/blob/d7037ccb/python3/frodokem.py#L204-L213
template<const size_t L>
constexpr std::array<uint16_t, L>
compute_cdf(std::array<uint16_t, L> χ)
{
  std::array<uint16_t, L> T_χ;

  T_χ[0] = (χ[0] / 2) - 1;
  for (size_t z = 1; z < χ.size(); z++) {
    T_χ[z] = T_χ[0] + std::accumulate(χ.begin() + 1, χ.begin() + (z + 1), 0u);
  }

  return T_χ;
}

// Zero-centered CDF used for sampling, in {e}Frodo-640 KEM. These compile-time
// computed values must match second column of table A.4
constexpr auto Frodo640_Tχ = compute_cdf(Frodo640_χ);

// Zero-centered CDF used for sampling, in {e}Frodo-976 KEM. These compile-time
// computed values must match third column of table A.4
constexpr auto Frodo976_Tχ = compute_cdf(Frodo976_χ);

// Zero-centered CDF used for sampling, in {e}Frodo-976 KEM. These compile-time
// computed values must match fourth column of table A.4
constexpr auto Frodo1344_Tχ = compute_cdf(Frodo1344_χ);

// Given a random 16 -bit wide value r and a CDF table Tχ, this routine
// can be used for sampling e ∈ Z from the distribution χ, following algorithm
// described in section 7.4 of the FrodoKEM specification.
//
// Note, this routine is implemented with constant-timeness in mind, but
// compilers are free to optimize, so it can be better idea to inspect generated
// assembly rather than just trusting that this implementation will always be
// constant-time on all targets.
template<const size_t D, const size_t L, const std::array<uint16_t, L> Tχ>
inline constexpr zq::zq_t<D>
sample(const uint16_t r)
{
  const uint16_t t = r >> 1;
  uint16_t e = 0;

  for (size_t z = 0; z < L - 1; z++) {
    const auto br = subtle::ct_gt<uint16_t, uint32_t>(t, Tχ[z]);
    e += subtle::ct_select<uint32_t, uint16_t>(br, 1, 0);
  }

  // Inspired from
  // https://github.com/microsoft/PQCrypto-LWEKE/blob/d7037ccb/src/noise.c#L26-L27
  const uint16_t r0 = r & 0b1;
  return zq::zq_t<D>(((-r0) ^ e) + r0);
}

// Given a bit string of length n1 x n2 x 16 -bits ( r ), this routine can be
// used for sampling an error matrix of dimension n1 x n2 s.t. all elements ∈ Z,
// following algorithm described in section 7.5 of FrodoKEM specification.
//
// - r is a byte array of length n1 x n2 x (16/ 8) -bytes.
// - e is a matrix of dimension n1 x n2, over Z.
template<const size_t n, const size_t n1, const size_t n2, const size_t D>
inline constexpr matrix::matrix<n1, n2, D>
sample_matrix(std::span<const uint8_t, 16 * n1 * n2 / 8> r)
{
  matrix::matrix<n1, n2, D> e{};

  size_t moff = 0;
  size_t boff = 0;

  while (moff < e.element_count()) {
    const uint16_t tmp = (static_cast<uint16_t>(r[boff + 1]) << 8) |
                         (static_cast<uint16_t>(r[boff + 0]) << 0);

    if constexpr (n == 640) {
      e[moff] = sample<D, 13, Frodo640_Tχ>(tmp);
    } else if constexpr (n == 976) {
      e[moff] = sample<D, 11, Frodo976_Tχ>(tmp);
    } else if constexpr (n == 1344) {
      e[moff] = sample<D, 7, Frodo1344_Tχ>(tmp);
    }

    moff += 1;
    boff += 2;
  }

  return e;
}

}
