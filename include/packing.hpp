#pragma once
#include "params.hpp"
#include "utils.hpp"
#include "zq.hpp"

// Packing matrices modulo Q to bit strings and vice versa
namespace packing {

// Given a matrix of dimension n1 x n2 s.t. its elements ∈ Zq, this routine can
// be used for packing the matrix into a bit string of length n1 x n2 x D -bits
// s.t. Q = 1 << D, following algorithm 3 of FrodoKEM specification.
//
// Note, we're dealing with byte oriented API, this routine packs matrix as a
// byte array of length (n1 * n2 * D + 7) / 8.
template<const size_t n1, const size_t n2, const uint32_t Q>
inline void
matrix_pack(
  const zq::zq_t<Q>* const __restrict mat, // matrix of dimension n1 x n2
  uint8_t* const __restrict arr            // byte len ⌈(n1 * n2 * D) / 8⌋
  )
  requires(frodo_params::check_q(Q))
{
  constexpr size_t D = frodo_utils::log2(Q);

  if constexpr (D == 15ul) {
    constexpr uint32_t mask8 = 0xffu;
    constexpr uint32_t mask7 = mask8 >> 1;
    constexpr uint32_t mask6 = mask7 >> 1;
    constexpr uint32_t mask5 = mask6 >> 1;
    constexpr uint32_t mask4 = mask5 >> 1;
    constexpr uint32_t mask3 = mask4 >> 1;
    constexpr uint32_t mask2 = mask3 >> 1;
    constexpr uint32_t mask1 = mask2 >> 1;

    size_t moff = 0;
    size_t boff = 0;

    while (moff < (n1 * n2)) {
      const auto v0 = mat[moff + 0].get_value();
      const auto v1 = mat[moff + 1].get_value();

      arr[boff + 0] = v0 & mask8;
      arr[boff + 1] = ((v1 & mask1) << 7) | ((v0 >> 8) & mask7);

      const auto v2 = mat[moff + 2].get_value();

      arr[boff + 2] = (v1 >> 1) & mask8;
      arr[boff + 3] = ((v2 & mask2) << 6) | ((v1 >> 9) & mask6);

      const auto v3 = mat[moff + 3].get_value();

      arr[boff + 4] = (v2 >> 2) & mask8;
      arr[boff + 5] = ((v3 & mask3) << 5) | ((v2 >> 10) & mask5);

      const auto v4 = mat[moff + 4].get_value();

      arr[boff + 6] = (v3 >> 3) & mask8;
      arr[boff + 7] = ((v4 & mask4) << 4) | ((v3 >> 11) & mask4);

      const auto v5 = mat[moff + 5].get_value();

      arr[boff + 8] = (v4 >> 4) & mask8;
      arr[boff + 9] = ((v5 & mask5) << 3) | ((v4 >> 12) & mask3);

      const auto v6 = mat[moff + 6].get_value();

      arr[boff + 10] = (v5 >> 5) & mask8;
      arr[boff + 11] = ((v6 & mask6) << 2) | ((v5 >> 13) & mask2);

      const auto v7 = mat[moff + 7].get_value();

      arr[boff + 12] = (v6 >> 6) & mask8;
      arr[boff + 13] = ((v7 & mask7) << 1) | ((v6 >> 14) & mask1);
      arr[boff + 14] = (v7 >> 7) & mask8;

      moff += 8;
      boff += 15;
    }
  } else if constexpr (D == 16ul) {
    constexpr uint32_t mask = 0xffu;

    size_t moff = 0;
    size_t boff = 0;

    while (moff < (n1 * n2)) {
      const auto v = mat[moff].get_value();

      arr[boff + 0] = (v >> 0) & mask;
      arr[boff + 1] = (v >> 8) & mask;

      moff += 1;
      boff += 2;
    }
  }
}

// Given a bit string of length n1 x n2 x D -bits ( as a byte array of length
// (n1 x n2 x D + 7) / 8 -bytes ), this routine can be used for unpacking
// contiguous ( D -many ) bits into a n1 x n2 matrix over Zq s.t. q = 1 << D,
// following algorithm 4 of FrodoKEM specification.
template<const size_t n1, const size_t n2, const uint32_t Q>
inline void
matrix_unpack(
  const uint8_t* const __restrict arr, // byte len ⌈(n1 * n2 * D) / 8⌋
  zq::zq_t<Q>* const __restrict mat    // matrix of dimension n1 x n2
  )
  requires(frodo_params::check_q(Q))
{
  // alias, so that I've to type lesser !
  using Zq = zq::zq_t<Q>;

  constexpr size_t D = frodo_utils::log2(Q);
  constexpr size_t bit_len = n1 * n2 * D;
  constexpr size_t byte_len = (bit_len + 7) / 8;

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
      mat[moff + 0] = Zq((static_cast<uint32_t>(arr[boff + 1] & mask7) << 8) |
                         static_cast<uint32_t>(arr[boff + 0]));
      mat[moff + 1] = Zq((static_cast<uint32_t>(arr[boff + 3] & mask6) << 9) |
                         (static_cast<uint32_t>(arr[boff + 2]) << 1) |
                         static_cast<uint32_t>(arr[boff + 1] >> 7));
      mat[moff + 2] = Zq((static_cast<uint32_t>(arr[boff + 5] & mask5) << 10) |
                         (static_cast<uint32_t>(arr[boff + 4]) << 2) |
                         static_cast<uint32_t>(arr[boff + 3] >> 6));
      mat[moff + 3] = Zq((static_cast<uint32_t>(arr[boff + 7] & mask4) << 11) |
                         (static_cast<uint32_t>(arr[boff + 6]) << 3) |
                         static_cast<uint32_t>(arr[boff + 5] >> 5));
      mat[moff + 4] = Zq((static_cast<uint32_t>(arr[boff + 9] & mask3) << 12) |
                         (static_cast<uint32_t>(arr[boff + 8]) << 4) |
                         static_cast<uint32_t>(arr[boff + 7] >> 4));
      mat[moff + 5] = Zq((static_cast<uint32_t>(arr[boff + 11] & mask2) << 13) |
                         (static_cast<uint32_t>(arr[boff + 10]) << 5) |
                         static_cast<uint32_t>(arr[boff + 9] >> 3));
      mat[moff + 6] = Zq((static_cast<uint32_t>(arr[boff + 13] & mask1) << 14) |
                         (static_cast<uint32_t>(arr[boff + 12]) << 6) |
                         static_cast<uint32_t>(arr[boff + 11] >> 2));
      mat[moff + 7] = Zq((static_cast<uint32_t>(arr[boff + 14]) << 7) |
                         static_cast<uint32_t>(arr[boff + 13] >> 1));

      boff += 15;
      moff += 8;
    }
  } else if constexpr (D == 16ul) {
    size_t boff = 0;
    size_t moff = 0;

    while (boff < byte_len) {
      mat[moff] = Zq((static_cast<uint32_t>(arr[boff + 1]) << 8) |
                     static_cast<uint32_t>(arr[boff + 0]));

      boff += 2;
      moff += 1;
    }
  }
}

}
