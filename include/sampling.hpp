#pragma once
#include "params.hpp"
#include "subtle.hpp"
#include "zq.hpp"
#include <array>
#include <cstdint>
#include <numeric>

// Sampling from the error distribution
namespace sampling {

// Discrete, symmetric error distribution over Z, centered at 0, for Frodo-640,
// as given on table 3 of FrodoKEM specification.
constexpr std::array<uint32_t, 13> Frodo640_χ = { 9288, 8720, 7216, 5264, 3384,
                                                  1918, 958,  422,  164,  56,
                                                  17,   4,    1 };

// Discrete, symmetric error distribution over Z, centered at 0, for Frodo-976,
// as given on table 3 of FrodoKEM specification.
constexpr std::array<uint32_t, 11> Frodo976_χ = { 11278, 10277, 7774, 4882,
                                                  2545,  1101,  396,  118,
                                                  29,    6,     1 };

// Discrete, symmetric error distribution over Z, centered at 0, for Frodo-1344,
// as given on table 3 of FrodoKEM specification.
constexpr std::array<uint32_t, 7> Frodo1344_χ = { 18286, 14320, 6876, 2023,
                                                  364,   40,    2 };

// Compile-time compute a zero-centred CDF, suitable for sampling using a
// uniform random value, following equations provided in section 2.2.4 of
// FrodoKEM specification.
//
// You can find reference implementation @
// https://github.com/microsoft/PQCrypto-LWEKE/blob/d7037ccb/python3/frodokem.py#L204-L213
template<const size_t L>
constexpr std::array<uint32_t, L>
compute_cdf(std::array<uint32_t, L> χ)
{
  std::array<uint32_t, L> T_χ;

  T_χ[0] = (χ[0] / 2) - 1;
  for (size_t z = 1; z < χ.size(); z++) {
    T_χ[z] = T_χ[0] + std::accumulate(χ.begin() + 1, χ.begin() + (z + 1), 0u);
  }

  return T_χ;
}

// Zero-centred CDF used for sampling, in Frodo-640 KEM
constexpr auto Frodo640_Tχ = compute_cdf(Frodo640_χ);

// Zero-centred CDF used for sampling, in Frodo-976 KEM
constexpr auto Frodo976_Tχ = compute_cdf(Frodo976_χ);

// Zero-centred CDF used for sampling, in Frodo-976 KEM
constexpr auto Frodo1344_Tχ = compute_cdf(Frodo1344_χ);

// Given a random len_χ -bit wide value r and a CDF table Tχ, this routine
// can be used for sampling e ∈ Z from the distribution χ, following algorithm 5
// of the FrodoKEM specification.
//
// Note, this routine is implemented with constant-timeness in mind, but
// compilers are free to optimize, so it can be better idea to inspect generated
// assembly rather than just trusting that this implementation will always be
// constant-time on all targets.
template<const size_t len_χ, const size_t L>
int32_t
sample(const uint32_t r, std::array<uint32_t, L> Tχ)
  requires(frodo_params::check_len_χ(len_χ))
{
  constexpr uint32_t mask = (1u << len_χ) - 1;
  const uint32_t t = (r & mask) >> 1;
  uint32_t e = 0;

  for (size_t z = 0; z < L - 1; z++) {
    const auto br = subtle::ct_gt<uint32_t, uint32_t>(t, Tχ[z]);
    e += subtle::ct_select(br, 1, 0);
  }

  const uint32_t r0 = r & 1u;
  const int32_t sign = -static_cast<int32_t>(r0);
  return sign * static_cast<int32_t>(e);
}

}
