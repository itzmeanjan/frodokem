#pragma once
#include "matrix.hpp"
#include "params.hpp"
#include "utils.hpp"
#include "zq.hpp"
#include <span>

// Packing matrices modulo Q to bit strings and vice versa
namespace packing {

// Given a matrix of dimension n1 x n2 s.t. its elements ∈ Zq, this routine can
// be used for packing the matrix into a bit string of length n1 x n2 x D -bits
// s.t. Q = 1 << D, following algorithm described in section 7.3 of FrodoKEM
// specification.
//
// Note, we're dealing with byte oriented API, this routine packs matrix as a
// byte array of length (n1 * n2 * D + 7) / 8.
template<size_t n1, size_t n2, size_t D>
inline constexpr void
pack(const matrix::matrix<n1, n2, D>& mat,
     std::span<uint8_t, (n1 * n2 * D + 7) / 8> arr)
  requires(frodo_params::check_d(D))
{
  if constexpr (D == 15ul) {
    constexpr uint16_t mask14 = 0x3fff;
    constexpr uint16_t mask13 = mask14 >> 1;
    constexpr uint16_t mask12 = mask13 >> 1;
    constexpr uint16_t mask11 = mask12 >> 1;
    constexpr uint16_t mask10 = mask11 >> 1;
    constexpr uint16_t mask9 = mask10 >> 1;
    constexpr uint16_t mask8 = mask9 >> 1;
    constexpr uint16_t mask7 = mask8 >> 1;
    constexpr uint16_t mask6 = mask7 >> 1;
    constexpr uint16_t mask5 = mask6 >> 1;
    constexpr uint16_t mask4 = mask5 >> 1;
    constexpr uint16_t mask3 = mask4 >> 1;
    constexpr uint16_t mask2 = mask3 >> 1;
    constexpr uint16_t mask1 = mask2 >> 1;

    size_t moff = 0;
    size_t boff = 0;

    while (moff < mat.element_count()) {
      const auto v0 = mat[moff + 0].to_canonical();
      const auto v1 = mat[moff + 1].to_canonical();

      arr[boff + 0] = (v0 >> 7) & mask8;
      arr[boff + 1] = ((v0 & mask7) << 1) | ((v1 >> 14) & mask1);

      const auto v2 = mat[moff + 2].to_canonical();

      arr[boff + 2] = (v1 & mask14) >> 6;
      arr[boff + 3] = ((v1 & mask6) << 2) | ((v2 >> 13) & mask2);

      const auto v3 = mat[moff + 3].to_canonical();

      arr[boff + 4] = (v2 & mask13) >> 5;
      arr[boff + 5] = ((v2 & mask5) << 3) | ((v3 >> 12) & mask3);

      const auto v4 = mat[moff + 4].to_canonical();

      arr[boff + 6] = (v3 & mask12) >> 4;
      arr[boff + 7] = ((v3 & mask4) << 4) | ((v4 >> 11) & mask4);

      const auto v5 = mat[moff + 5].to_canonical();

      arr[boff + 8] = (v4 & mask11) >> 3;
      arr[boff + 9] = ((v4 & mask3) << 5) | ((v5 >> 10) & mask5);

      const auto v6 = mat[moff + 6].to_canonical();

      arr[boff + 10] = (v5 & mask10) >> 2;
      arr[boff + 11] = ((v5 & mask2) << 6) | ((v6 >> 9) & mask6);

      const auto v7 = mat[moff + 7].to_canonical();

      arr[boff + 12] = (v6 & mask9) >> 1;
      arr[boff + 13] = ((v6 & mask1) << 7) | ((v7 >> 8) & mask7);
      arr[boff + 14] = v7 & mask8;

      moff += 8;
      boff += 15;
    }
  } else if constexpr (D == 16ul) {
    constexpr uint16_t mask = 0xff;

    size_t moff = 0;
    size_t boff = 0;

    while (moff < mat.element_count()) {
      const auto v = mat[moff].to_canonical();

      arr[boff + 0] = (v >> 8) & mask;
      arr[boff + 1] = (v >> 0) & mask;

      moff += 1;
      boff += 2;
    }
  }
}

// Given a bit string of length n1 x n2 x D -bits ( as a byte array of length
// (n1 x n2 x D + 7) / 8 -bytes ), this routine can be used for unpacking
// contiguous ( D -many ) bits into a n1 x n2 matrix over Zq s.t. q = 1 << D,
// following algorithm described in section 7.3 of FrodoKEM specification.
template<size_t n1, size_t n2, size_t D>
inline constexpr matrix::matrix<n1, n2, D>
unpack(std::span<const uint8_t, (n1 * n2 * D + 7) / 8> arr)
  requires(frodo_params::check_d(D))
{
  // alias, so that I've to type lesser !
  using Zq = zq::zq_t<D>;

  constexpr size_t byte_len = arr.size();
  matrix::matrix<n1, n2, D> mat{};

  if constexpr (D == 15ul) {
    constexpr uint8_t mask7 = 0xff >> 1;
    constexpr uint8_t mask6 = mask7 >> 1;
    constexpr uint8_t mask5 = mask6 >> 1;
    constexpr uint8_t mask4 = mask5 >> 1;
    constexpr uint8_t mask3 = mask4 >> 1;
    constexpr uint8_t mask2 = mask3 >> 1;
    constexpr uint8_t mask1 = mask2 >> 1;

    size_t boff = 0;
    size_t moff = 0;

    while (boff < byte_len) {
      mat[moff + 0] = Zq((static_cast<uint16_t>(arr[boff + 0]) << 7) |
                         static_cast<uint16_t>(arr[boff + 1] >> 1));
      mat[moff + 1] = Zq((static_cast<uint16_t>(arr[boff + 1] & mask1) << 14) |
                         (static_cast<uint16_t>(arr[boff + 2]) << 6) |
                         static_cast<uint16_t>(arr[boff + 3] >> 2));
      mat[moff + 2] = Zq((static_cast<uint16_t>(arr[boff + 3] & mask2) << 13) |
                         (static_cast<uint16_t>(arr[boff + 4]) << 5) |
                         static_cast<uint16_t>(arr[boff + 5] >> 3));
      mat[moff + 3] = Zq((static_cast<uint16_t>(arr[boff + 5] & mask3) << 12) |
                         (static_cast<uint16_t>(arr[boff + 6]) << 4) |
                         static_cast<uint16_t>(arr[boff + 7] >> 4));
      mat[moff + 4] = Zq((static_cast<uint16_t>(arr[boff + 7] & mask4) << 11) |
                         (static_cast<uint16_t>(arr[boff + 8]) << 3) |
                         static_cast<uint16_t>(arr[boff + 9] >> 5));
      mat[moff + 5] = Zq((static_cast<uint16_t>(arr[boff + 9] & mask5) << 10) |
                         (static_cast<uint16_t>(arr[boff + 10]) << 2) |
                         static_cast<uint16_t>(arr[boff + 11] >> 6));
      mat[moff + 6] = Zq((static_cast<uint16_t>(arr[boff + 11] & mask6) << 9) |
                         (static_cast<uint16_t>(arr[boff + 12]) << 1) |
                         static_cast<uint16_t>(arr[boff + 13] >> 7));
      mat[moff + 7] = Zq((static_cast<uint16_t>(arr[boff + 13] & mask7) << 8) |
                         static_cast<uint16_t>(arr[boff + 14]));

      boff += 15;
      moff += 8;
    }
  } else if constexpr (D == 16ul) {
    size_t boff = 0;
    size_t moff = 0;

    while (boff < byte_len) {
      mat[moff] = Zq((static_cast<uint16_t>(arr[boff + 0]) << 8) |
                     static_cast<uint16_t>(arr[boff + 1]) << 0);

      boff += 2;
      moff += 1;
    }
  }

  return mat;
}

}
