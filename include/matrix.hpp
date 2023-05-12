#pragma once
#include "zq.hpp"
#include <array>
#include <span>

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
};

// Given a matrix (src) of dimension m x n over Zq, this routine is used for
// computing its transpose matrix (dst) of dimension n x m.
template<const size_t m, const size_t n, const uint32_t Q>
inline void
transpose(const zq::zq_t<Q>* const __restrict src,
          zq::zq_t<Q>* const __restrict dst)
{
  for (size_t i = 0; i < n; i++) {
    for (size_t j = 0; j < m; j++) {
      dst[i * m + j] = src[j * n + i];
    }
  }
}

// Given two matrices (A, B) of same dimension, this routine can be used for
// adding two matrices, resulting into another matrix (C) of same dimension.
template<const size_t m, const size_t n, const uint32_t Q>
inline void
add(const zq::zq_t<Q>* const __restrict matA,
    const zq::zq_t<Q>* const __restrict matB,
    zq::zq_t<Q>* const __restrict matC)
{
  for (size_t i = 0; i < m * n; i++) {
    matC[i] = matA[i] + matB[i];
  }
}

// Given two matrices (A, B) of same dimension, this routine can be used for
// subtracting B from A, resulting into another matrix (C) of same dimension.
template<const size_t m, const size_t n, const uint32_t Q>
inline void
sub(const zq::zq_t<Q>* const __restrict matA,
    const zq::zq_t<Q>* const __restrict matB,
    zq::zq_t<Q>* const __restrict matC)
{
  for (size_t i = 0; i < m * n; i++) {
    matC[i] = matA[i] - matB[i];
  }
}

// Given two matrices A ( of dimension l_m x l_n ) and B ( of dimension r_m x
// r_n ) s.t. l_n == r_m, this routine can be used for multiplying them,
// resulting into another matrix (C) of dimension l_m x r_n.
template<const size_t l_m,
         const size_t l_n,
         const size_t r_m,
         const size_t r_n,
         const uint32_t Q>
inline void
mul(const zq::zq_t<Q>* const __restrict matA,
    const zq::zq_t<Q>* const __restrict matB,
    zq::zq_t<Q>* const __restrict matC)
  requires(l_n == r_m)
{
  for (size_t i = 0; i < l_m; i++) {
    for (size_t j = 0; j < r_n; j++) {
      zq::zq_t<Q> tmp(0);

      for (size_t k = 0; k < l_n; k++) {
        tmp += (matA[i * l_n + k] * matB[k * r_n + j]);
      }
      matC[i * r_n + j] = tmp;
    }
  }
}

}
