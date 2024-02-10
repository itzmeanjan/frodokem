#pragma once
#include "prng.hpp"
#include "subtle.hpp"
#include "zq.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <type_traits>

// Operations on Matrices over Zq
namespace matrix {

// Wrapper type encapsulating ops on matrices s.t. elements ∈ Zq | q = 2^D
template<size_t rows, size_t cols, size_t D>
struct matrix
{
private:
  std::array<zq::zq_t<D>, rows * cols> elements{};

public:
  inline constexpr matrix() = default;

  // Given linear index of matrix, returns reference to requested element.
  inline constexpr zq::zq_t<D>& operator[](const size_t lin_idx) { return this->elements[lin_idx]; }

  // Given linear index of matrix, returns const reference to requested element.
  inline constexpr const zq::zq_t<D>& operator[](const size_t lin_idx) const { return this->elements[lin_idx]; }

  // Given row and column index of matrix, returns reference to requested
  // element.
  inline constexpr zq::zq_t<D>& operator[](std::pair<size_t, size_t> idx) { return this->elements[idx.first * cols + idx.second]; }

  // Given row and column index of matrix, returns const reference to requested
  // element.
  inline constexpr const zq::zq_t<D>& operator[](std::pair<size_t, size_t> idx) const { return this->elements[idx.first * cols + idx.second]; }

  // Returns # -of rows in matrix M
  inline constexpr size_t row_count() const { return rows; }

  // Returns # -of cols in matrix M
  inline constexpr size_t col_count() const { return cols; }

  // Returns # -of elements in matrix M
  inline constexpr size_t element_count() const { return rows * cols; }

  // Given a matrix M of dimension m x n, this routine is used for computing its
  // transpose M' s.t. resulting matrix's dimension becomes n x m.
  inline constexpr matrix<cols, rows, D> transpose() const
  {
    matrix<cols, rows, D> res{};

    for (size_t i = 0; i < cols; i++) {
      for (size_t j = 0; j < rows; j++) {
        res[{ i, j }] = (*this)[{ j, i }];
      }
    }

    return res;
  }

  // Given two matrices A, B of same dimension, this routine can be used for
  // performing matrix addition over Zq, returning a matrix of same dimension.
  inline constexpr matrix<rows, cols, D> operator+(const matrix<rows, cols, D>& rhs) const
  {
    matrix<rows, cols, D> res{};

    for (size_t i = 0; i < res.element_count(); i++) {
      res[i] = (*this)[i] + rhs[i];
    }

    return res;
  }

  // Given two matrices A, B of same dimension, this routine can be used for
  // subtracting B from A, resulting into another matrix C of same dimension.
  inline constexpr matrix<rows, cols, D> operator-(const matrix<rows, cols, D>& rhs) const
  {
    matrix<rows, cols, D> res{};

    for (size_t i = 0; i < res.element_count(); i++) {
      res[i] = (*this)[i] - rhs[i];
    }

    return res;
  }

  // Given two matrices A ( of dimension rows x cols ) and B ( of dimension
  // rhs_rows x rhs_cols ) s.t. cols == rhs_rows, this routine can be used for
  // multiplying them over Zq, resulting into another matrix (C) of dimension
  // rows x rhs_cols.
  template<size_t rhs_rows, size_t rhs_cols>
  inline constexpr matrix<rows, rhs_cols, D> operator*(const matrix<rhs_rows, rhs_cols, D>& rhs) const
    requires(cols == rhs_rows)
  {
    matrix<rows, rhs_cols, D> res{};

    for (size_t i = 0; i < rows; i++) {
      for (size_t j = 0; j < rhs_cols; j++) {
        zq::zq_t<D> tmp(0);

        for (size_t k = 0; k < cols; k++) {
          tmp += (*this)[{ i, k }] * rhs[{ k, j }];
        }

        res[{ i, j }] = tmp;
      }
    }

    return res;
  }

  // Given two matrices A, B of same dimension, this routine can be used for
  // testing equality of A and B i.e. only returns true if A == B.
  inline constexpr bool operator==(const matrix<rows, cols, D>& rhs) const { return std::ranges::equal(this->elements, rhs.elements); }

  // Given two matrices A, B of same dimension, this routine can be used for
  // constant-time equality test between A and B s.t. it returns truth value ( =
  // 0xffffffff ) in case A == B or it returns false value ( = 0x00 ).
  inline constexpr uint32_t ct_equal(const matrix<rows, cols, D>& rhs) const
  {
    uint32_t res = -1u;

    for (size_t i = 0; i < this->element_count(); i++) {
      res &= subtle::ct_eq<uint16_t, uint32_t>(this->elements[i].to_canonical(), rhs.elements[i].to_canonical());
    }

    return res;
  }

  // Given a seed of length len_seed_A -bits, this routine can be used for
  // deterministically generating a pseudorandom matrix of dimension n x n,
  // using SHAKE128 XOF, following algorithm described in section 7.6.2 of
  // FrodoKEM specification.
  template<size_t len_seed_A>
  inline static constexpr matrix<rows, cols, D> generate(std::span<const uint8_t, (len_seed_A + 7) / 8> seed)
    requires(rows == cols)
  {
    constexpr size_t seed_bytes = seed.size();

    std::array<uint8_t, 2 + seed_bytes> buf{};
    std::array<uint8_t, cols * 2> dig{};

    std::memcpy(buf.data() + 2, seed.data(), seed_bytes);

    matrix<rows, cols, D> mat{};

    for (size_t i = 0; i < rows; i++) {
      const uint16_t ridx = static_cast<uint16_t>(i);

      buf[0] = (ridx >> 0) & 0xff;
      buf[1] = (ridx >> 8) & 0xff;

      shake128::shake128_t hasher{};

      hasher.absorb(buf);
      hasher.finalize();
      hasher.squeeze(dig);

      for (size_t j = 0; j < cols; j++) {
        const uint16_t word = (static_cast<uint16_t>(dig[2 * j + 1]) << 8) | (static_cast<uint16_t>(dig[2 * j + 0]) << 0);

        mat[{ i, j }] = zq::zq_t<D>(word);
      }
    }

    return mat;
  }

  // Computes a random matrix, while reading pseudo random bytes from PRNG.
  inline static constexpr matrix<rows, cols, D> random(prng::prng_t& prng)
  {
    matrix<rows, cols, D> mat{};

    for (size_t i = 0; i < mat.element_count(); i++) {
      mat[i] = zq::zq_t<D>::random_value(prng);
    }

    return mat;
  }

  // Given a matrix M of dimension m x n, this routine can be used for
  // serializing each of its elements as two little-endian bytes and
  // concatenating them in order to compute a byte array of length m * n * 2.
  inline void write_as_le_bytes(std::span<uint8_t, rows * cols * 2> bytes) const
  {
    for (size_t i = 0; i < this->element_count(); i++) {
      const size_t boff = i * 2;

      const auto word = this->elements[i].to_raw();
      bytes[boff + 0] = (word >> 0) & 0xff;
      bytes[boff + 1] = (word >> 8) & 0xff;
    }
  }

  // Given a byte array of length m * n * 2, this routine can be used for
  // deserializing it as a matrix of dimension m x n s.t. each matrix element is
  // computed by interpreting two consecutive bytes in little-endian order.
  inline static matrix<rows, cols, D> read_from_le_bytes(std::span<const uint8_t, rows * cols * 2> bytes)
  {
    constexpr size_t blen = bytes.size();
    matrix<rows, cols, D> res{};

    size_t boff = 0;
    size_t moff = 0;

    while (boff < blen) {
      const uint16_t word = (static_cast<uint16_t>(bytes[boff + 1]) << 8) | (static_cast<uint16_t>(bytes[boff + 0]) << 0);
      res[moff] = zq::zq_t<D>(word);

      boff += 2;
      moff += 1;
    }

    return res;
  }
};

}
