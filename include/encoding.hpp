#pragma once
#include "matrix.hpp"
#include "params.hpp"
#include "zq.hpp"
#include <span>

// Encoding bit strings to matrix and vice versa.
namespace encoding {

// Given a bit string ( of length m x n x B -bits ) as byte array of length (m x
// n x B + 7)/ 8 -bytes, this routine treats each B -bit wide sub-string as an
// integer k ∈ [0, 2^B), which is encoded as an element of Zq s.t. q = 2^D and B
// <= D using `ec()` function, returning a matrix of dimension m x n over Zq,
// following algorithm described in section 7.2 of FrodoKEM specification.
template<size_t m, size_t n, size_t D, size_t B>
inline constexpr matrix::matrix<m, n, D>
encode(std::span<const uint8_t, (m * n * B + 7) / 8> arr)
  requires((m == n) && frodo_params::check_b(B) && (B <= D))
{
  // alias, so that I've to type lesser !
  using Zq = zq::zq_t<D>;

  constexpr size_t byte_len = arr.size();
  matrix::matrix<m, n, D> mat{};

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

  return mat;
}

// Given a matrix of dimension m x n s.t. its elements ∈ Zq, this routine can be
// used for decoding it into a bit string of length m x n x B -bits, rounding to
// the B most significant bits of each matrix entry, by applying `dc()`
// function, returning a byte array of length (m x n x B + 7)/ 8 -bytes,
// following algorithm described in section 7.2 of FrodoKEM specification.
template<size_t m, size_t n, size_t D, size_t B>
inline constexpr void
decode(const matrix::matrix<m, n, D>& mat,
       std::span<uint8_t, (m * n * B + 7) / 8> arr)
  requires((m == n) && frodo_params::check_d(D) && frodo_params::check_b(B) &&
           (B <= D))
{
  if constexpr (B == 2) {
    constexpr uint16_t mask = 0b11;

    size_t moff = 0;
    size_t boff = 0;

    while (moff < mat.element_count()) {
      arr[boff] = ((mat[moff + 3].template decode<B>() & mask) << 6) |
                  ((mat[moff + 2].template decode<B>() & mask) << 4) |
                  ((mat[moff + 1].template decode<B>() & mask) << 2) |
                  ((mat[moff + 0].template decode<B>() & mask) << 0);

      moff += 4;
      boff += 1;
    }
  } else if constexpr (B == 3) {
    constexpr uint16_t mask3 = 0b111;
    constexpr uint16_t mask2 = mask3 >> 1;
    constexpr uint16_t mask1 = mask2 >> 1;

    size_t moff = 0;
    size_t boff = 0;

    while (moff < mat.element_count()) {
      const auto t0 = mat[moff + 0].template decode<B>() & mask3;
      const auto t1 = mat[moff + 1].template decode<B>() & mask3;
      const auto t2 = mat[moff + 2].template decode<B>() & mask3;

      arr[boff] = ((t2 & mask2) << 6) | (t1 << 3) | t0;

      const auto t3 = mat[moff + 3].template decode<B>() & mask3;
      const auto t4 = mat[moff + 4].template decode<B>() & mask3;
      const auto t5 = mat[moff + 5].template decode<B>() & mask3;

      arr[boff + 1] = ((t5 & mask1) << 7) | (t4 << 4) | (t3 << 1) | (t2 >> 2);

      const auto t6 = mat[moff + 6].template decode<B>() & mask3;
      const auto t7 = mat[moff + 7].template decode<B>() & mask3;

      arr[boff + 2] = (t7 << 5) | (t6 << 2) | (t5 >> 1);

      moff += 8;
      boff += 3;
    }
  } else if constexpr (B == 4) {
    constexpr uint16_t mask = 0b1111;

    size_t moff = 0;
    size_t boff = 0;

    while (moff < mat.element_count()) {
      arr[boff] = ((mat[moff + 1].template decode<B>() & mask) << 4) |
                  ((mat[moff + 0].template decode<B>() & mask) << 0);

      moff += 2;
      boff += 1;
    }
  }
}

}
