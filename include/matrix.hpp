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

// Wrapper type encapsulating operations on matrices s.t. its elements ∈ Zq
template<const size_t rows, const size_t cols, const uint32_t Q>
struct matrix
{
private:
  std::array<zq::zq_t<Q>, rows * cols> elements{};

public:
  inline constexpr matrix() = default;

  // Given linear index of matrix, returns reference to requested element.
  inline constexpr zq::zq_t<Q>& operator[](const size_t lin_idx)
  {
    return this->elements[lin_idx];
  }

  // Given linear index of matrix, returns const reference to requested element.
  inline constexpr const zq::zq_t<Q>& operator[](const size_t lin_idx) const
  {
    return this->elements[lin_idx];
  }

  // Given row and column index of matrix, returns reference to requested
  // element.
  inline constexpr zq::zq_t<Q>& operator[](std::pair<size_t, size_t> idx)
  {
    return this->elements[idx.first * cols + idx.second];
  }

  // Given row and column index of matrix, returns const reference to requested
  // element.
  inline constexpr const zq::zq_t<Q>& operator[](
    std::pair<size_t, size_t> idx) const
  {
    return this->elements[idx.first * cols + idx.second];
  }

  // Returns # -of rows in matrix M
  inline constexpr size_t row_count() const { return rows; }

  // Returns # -of cols in matrix M
  inline constexpr size_t col_count() const { return cols; }

  // Returns # -of elements in matrix M
  inline constexpr size_t element_count() const { return rows * cols; }

  // Given a matrix M of dimension m x n, this routine is used for computing its
  // transpose M' s.t. resulting matrix's dimension becomes n x m.
  inline constexpr matrix<cols, rows, Q> transpose() const
  {
    matrix<cols, rows, Q> res{};

    for (size_t i = 0; i < cols; i++) {
      for (size_t j = 0; j < rows; j++) {
        res[{ i, j }] = (*this)[{ j, i }];
      }
    }

    return res;
  }

  // Given two matrices A, B of same dimension, this routine can be used for
  // performing matrix addition over Zq, returning a matrix of same dimension.
  inline constexpr matrix<rows, cols, Q> operator+(
    const matrix<rows, cols, Q>& rhs) const
  {
    matrix<rows, cols, Q> res{};

    for (size_t i = 0; i < res.element_count(); i++) {
      res[i] = (*this)[i] + rhs[i];
    }

    return res;
  }

  // Given two matrices A, B of same dimension, this routine can be used for
  // subtracting B from A, resulting into another matrix C of same dimension.
  inline constexpr matrix<rows, cols, Q> operator-(
    const matrix<rows, cols, Q>& rhs) const
  {
    matrix<rows, cols, Q> res{};

    for (size_t i = 0; i < res.element_count(); i++) {
      res[i] = (*this)[i] - rhs[i];
    }

    return res;
  }

  // Given two matrices A ( of dimension rows x cols ) and B ( of dimension
  // rhs_rows x rhs_cols ) s.t. cols == rhs_rows, this routine can be used for
  // multiplying them over Zq, resulting into another matrix (C) of dimension
  // rows x rhs_cols.
  template<const size_t rhs_rows, const size_t rhs_cols>
  inline constexpr matrix<rows, rhs_cols, Q> operator*(
    const matrix<rhs_rows, rhs_cols, Q>& rhs) const
    requires(cols == rhs_rows)
  {
    matrix<rows, rhs_cols, Q> res{};

    for (size_t i = 0; i < rows; i++) {
      for (size_t j = 0; j < rhs_cols; j++) {
        zq::zq_t<Q> tmp(0);

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
  inline constexpr bool operator==(const matrix<rows, cols, Q>& rhs) const
  {
    return std::ranges::equal(this->elements, rhs.elements);
  }

  // Given two matrices A, B of same dimension, this routine can be used for
  // constant-time equality test between A and B s.t. it returns truth value (
  // i.e. value of type T having all of its bits set to 1 ) in case A == B or it
  // returns false value ( = 0 value of type T ).
  template<typename T>
  inline constexpr T ct_equal(const matrix<rows, cols, Q>& rhs) const
    requires(std::is_unsigned_v<T>)
  {
    T res = static_cast<T>(-1);

    for (size_t i = 0; i < this->element_count(); i++) {
      res &= subtle::ct_eq<uint32_t, T>(this->elements[i].get_value(),
                                        rhs.elements[i].get_value());
    }

    return res;
  }

  // Given a seed of length len_seed_A -bits, this routine can be used for
  // deterministically generating a pseudorandom matrix of dimension n x n,
  // using SHAKE128 XOF, following algorithm 8 of FrodoKEM specification.
  template<const size_t len_seed_A>
  inline static constexpr matrix<rows, cols, Q> generate(
    std::span<const uint8_t, (len_seed_A + 7) / 8> seed)
    requires(rows == cols)
  {
    constexpr size_t seed_bytes = seed.size();

    uint8_t buf[2 + seed_bytes];
    uint8_t dig[cols * 2];
    std::memcpy(buf + 2, seed.data(), seed_bytes);

    matrix<rows, cols, Q> mat{};

    for (size_t i = 0; i < rows; i++) {
      const uint16_t ridx = static_cast<uint16_t>(i);

      buf[0] = (ridx >> 0) & 0xff;
      buf[1] = (ridx >> 8) & 0xff;

      shake128::shake128 hasher{};

      hasher.hash(buf, sizeof(buf));
      hasher.read(dig, sizeof(dig));

      for (size_t j = 0; j < cols; j++) {
        const uint16_t word = (static_cast<uint16_t>(dig[2 * j + 1]) << 8) |
                              (static_cast<uint16_t>(dig[2 * j + 0]) << 0);

        mat[{ i, j }] = zq::zq_t<Q>(static_cast<uint32_t>(word));
      }
    }

    return mat;
  }

  // Computes a random matrix, while reading pseudo random bytes from PRNG.
  inline static constexpr matrix<rows, cols, Q> random(prng::prng_t& prng)
  {
    matrix<rows, cols, Q> mat{};

    for (size_t i = 0; i < mat.element_count(); i++) {
      mat[i] = zq::zq_t<Q>::random_value(prng);
    }

    return mat;
  }
};

}
