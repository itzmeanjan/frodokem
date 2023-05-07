#pragma once
#include "shake128.hpp"
#include "zq.hpp"
#include <cstdint>
#include <cstring>

// Pseudo-Random Matrix Generation
namespace gen_matrix {

// Given a seed of length len_seed_A -bits, this routine can be used for
// deterministically generating a pseudorandom matrix of dimension n x n, using
// SHAKE128 XOF, following algorithm 8 of FrodoKEM specification.
template<const size_t len_seed_A, const size_t n, const uint32_t Q>
inline void
gen(const uint8_t* const __restrict seed, zq::zq_t<Q>* const __restrict mat)
{
  constexpr size_t seed_bytes = (len_seed_A + 7) / 8;

  uint8_t buf[2 + seed_bytes];
  uint8_t dig[n * 2];
  std::memcpy(buf + 2, seed, seed_bytes);

  for (size_t i = 0; i < n; i++) {
    const size_t off = i * n;
    const uint16_t ridx = static_cast<uint16_t>(i);

    buf[0] = (ridx >> 0) & 0xff;
    buf[1] = (ridx >> 8) & 0xff;

    shake128::shake128 hasher;
    hasher.hash(buf, sizeof(buf));
    hasher.read(dig, sizeof(dig));

    for (size_t j = 0; j < n; j++) {
      const uint16_t word = (static_cast<uint16_t>(dig[2 * j + 1]) << 8) |
                            (static_cast<uint16_t>(dig[2 * j + 0]) << 0);

      mat[off + j] = zq::zq_t<Q>(static_cast<uint32_t>(word));
    }
  }
}

}
