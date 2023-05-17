#pragma once
#include "kem.hpp"
#include "prng.hpp"
#include "utils.hpp"
#include <algorithm>
#include <cassert>
#include <span>
#include <vector>

// Test functional correctness of FrodoKEM along with its components.
namespace test_frodo {

// Test if
//
// - generating a random Frodo KEM keypair
// - encapsulating shared secret, using public key
// - decapsulating shared secret, using private key
//
// works as expected.
template<const size_t n,
         const size_t m̄,
         const size_t n̄,
         const size_t lA,
         const size_t lSE,
         const size_t ls,
         const size_t lz,
         const size_t lss,
         const size_t lk,
         const size_t lμ,
         const size_t lpkh,
         const size_t lχ,
         const uint32_t q,
         const size_t b>
void
test_kem()
{
  namespace utils = frodo_utils;

  constexpr size_t pklen = utils::kem_pub_key_len(n, n̄, lA, q);
  constexpr size_t sklen = utils::kem_sec_key_len(n, n̄, ls, lA, lpkh, q);
  constexpr size_t ctlen = utils::kem_cipher_text_len(n, m̄, n̄, q);

  std::vector<uint8_t> s(ls / 8, 0);
  std::vector<uint8_t> seedSE(lSE / 8, 0);
  std::vector<uint8_t> z(lz / 8, 0);
  std::vector<uint8_t> pkey(pklen, 0);
  std::vector<uint8_t> skey(sklen, 0);
  std::vector<uint8_t> μ(lμ / 8, 0);
  std::vector<uint8_t> enc(ctlen, 0);
  std::vector<uint8_t> ss0(lss / 8, 0);
  std::vector<uint8_t> ss1(lss / 8, 0);

  std::span<uint8_t, ls / 8> _s{ s };
  std::span<uint8_t, lSE / 8> _seedSE{ seedSE };
  std::span<uint8_t, lz / 8> _z{ z };
  std::span<uint8_t, pklen> _pkey{ pkey };
  std::span<uint8_t, sklen> _skey{ skey };
  std::span<uint8_t, lμ / 8> _μ{ μ };
  std::span<uint8_t, ctlen> _enc{ enc };
  std::span<uint8_t, lss / 8> _ss0{ ss0 };
  std::span<uint8_t, lss / 8> _ss1{ ss1 };

  prng::prng_t prng;

  prng.read(_s.data(), _s.size());
  prng.read(_seedSE.data(), _seedSE.size());
  prng.read(_z.data(), _z.size());
  prng.read(_μ.data(), _μ.size());

  using namespace kem;

  keygen<n, n̄, lA, lSE, ls, lz, lpkh, lχ, q, b>(_s, _seedSE, _z, _pkey, _skey);
  encaps<n, m̄, n̄, lA, lSE, lss, lk, lμ, lpkh, lχ, q, b>(_μ, _pkey, _enc, _ss0);
  decaps<n, m̄, n̄, lA, lSE, ls, lss, lk, lμ, lpkh, lχ, q, b>(_skey, _enc, _ss1);

  assert(std::ranges::equal(ss0, ss1));
}

}
