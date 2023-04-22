#pragma once
#include "params.hpp"
#include "zq.hpp"

// Encoding bit strings to matrix and vice versa.
namespace encoding {

// Given a bit string ( of length m x n x B -bits ) as byte array, this routine
// encodes each B -bit wide sub-string as an integer k ∈ [0, 2^B), which is
// encoded as an element of Zq s.t. q = 2^D and B <= D.
template<const size_t m, const size_t n, const uint32_t Q, const size_t B>
inline void
matrix_encode(
  const uint8_t* const __restrict arr, // of length (m x n x B)/ 8 -bytes
  zq::zq_t<Q>* const __restrict mat    // matrix of dimension m x n
  )
  requires((m == n) && frodo_params::check_q(Q) && frodo_params::check_b(B))
{
  // alias, so that I've to type lesser !
  using Zq = zq::zq_t<Q>;

  constexpr size_t bit_len = m * n * B;
  constexpr size_t byte_len = bit_len / 8;

  if constexpr (B == 2) {
    constexpr uint8_t mask = 0b11;

    size_t boff = 0;
    size_t moff = 0;

    while (boff < byte_len) {
      mat[moff + 0] = Zq::template encode<B>((arr[boff] >> 0) & mask);
      mat[moff + 1] = Zq::template encode<B>((arr[boff] >> 2) & mask);
      mat[moff + 2] = Zq::template encode<B>((arr[boff] >> 4) & mask);
      mat[moff + 3] = Zq::template encode<B>((arr[boff] >> 6) & mask);

      boff += 1;
      moff += 4;
    }
  } else if constexpr (B == 3) {
    constexpr uint8_t mask3 = 0b111;
    constexpr uint8_t mask2 = 0b11;
    constexpr uint8_t mask1 = 0b1;

    size_t boff = 0;
    size_t moff = 0;

    while (boff < byte_len) {
      mat[moff + 0] = Zq::template encode<B>((arr[boff] >> 0) & mask3);
      mat[moff + 1] = Zq::template encode<B>((arr[boff] >> 3) & mask3);
      mat[moff + 2] = Zq::template encode<B>(((arr[boff + 1] & mask1) << 2) |
                                             ((arr[boff] >> 6) & mask2));
      mat[moff + 3] = Zq::template encode<B>((arr[boff + 1] >> 1) & mask3);
      mat[moff + 4] = Zq::template encode<B>((arr[boff + 1] >> 4) & mask3);
      mat[moff + 5] = Zq::template encode<B>(((arr[boff + 2] & mask2) << 1) |
                                             ((arr[boff + 1] >> 7) & mask1));
      mat[moff + 6] = Zq::template encode<B>((arr[boff + 2] >> 2) & mask3);
      mat[moff + 7] = Zq::template encode<B>(arr[boff + 2] >> 5);

      boff += 3;
      moff += 8;
    }
  } else if constexpr (B == 4) {
    constexpr uint8_t mask = 0b1111;

    size_t boff = 0;
    size_t moff = 0;

    while (boff < byte_len) {
      mat[moff + 0] = Zq::template encode<B>((arr[boff] >> 0) & mask);
      mat[moff + 1] = Zq::template encode<B>((arr[boff] >> 4) & mask);

      boff += 1;
      moff += 2;
    }
  }
}

}
