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
         const size_t n̄,
         const size_t len_A,
         const size_t len_sec,
         const size_t len_SE,
         const size_t len_salt,
         const size_t D,
         const size_t B>
void
test_kem()
{
  namespace utils = frodo_utils;

  constexpr size_t pklen = utils::kem_pub_key_len(n, n̄, len_A, D);
  constexpr size_t sklen = utils::kem_sec_key_len(n, n̄, len_sec, len_A, D);
  constexpr size_t ctlen = utils::kem_cipher_text_len(n, n̄, len_salt, D);

  std::vector<uint8_t> s(len_sec / 8, 0);
  std::vector<uint8_t> seedSE(len_SE / 8, 0);
  std::vector<uint8_t> z(len_A / 8, 0);
  std::vector<uint8_t> pkey(pklen, 0);
  std::vector<uint8_t> skey(sklen, 0);
  std::vector<uint8_t> μ(len_sec / 8, 0);
  std::vector<uint8_t> enc(ctlen, 0);
  std::vector<uint8_t> ss0(len_sec / 8, 0);
  std::vector<uint8_t> ss1(len_sec / 8, 0);

  std::span<uint8_t, len_sec / 8> _s{ s };
  std::span<uint8_t, len_SE / 8> _seedSE{ seedSE };
  std::span<uint8_t, len_A / 8> _z{ z };
  std::span<uint8_t, pklen> _pkey{ pkey };
  std::span<uint8_t, sklen> _skey{ skey };
  std::span<uint8_t, len_sec / 8> _μ{ μ };
  std::span<uint8_t, ctlen> _enc{ enc };
  std::span<uint8_t, len_sec / 8> _ss0{ ss0 };
  std::span<uint8_t, len_sec / 8> _ss1{ ss1 };

  prng::prng_t prng;

  prng.read(_s);
  prng.read(_seedSE);
  prng.read(_z);
  prng.read(_μ);

  using namespace kem;

  keygen<n, n̄, len_sec, len_SE, len_A, B, D>(_s, _seedSE, _z, _pkey, _skey);
  encaps<n, n̄, len_sec, len_SE, len_A, len_salt, B, D>(_μ, _pkey, _enc, _ss0);
  decaps<n, n̄, len_sec, len_SE, len_A, len_salt, D, B>(_skey, _enc, _ss1);

  assert(std::ranges::equal(ss0, ss1));
}

}
