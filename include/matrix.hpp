#pragma once
#include "zq.hpp"
#include <array>

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
