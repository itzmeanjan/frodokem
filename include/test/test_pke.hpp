#pragma once
#include "pke.hpp"
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
// - generating a random Frodo PKE keypair
// - encrypting a random fixed length message, using public key
// - decrypting cipher text, using private key
//
// works as expected.
template<const size_t n,
         const size_t l,
         const size_t m_bar,
         const size_t n_bar,
         const size_t lA,
         const size_t lSE,
         const size_t lχ,
         const uint32_t Q,
         const size_t B>
void
test_pke()
{
  namespace utils = frodo_utils;

  constexpr size_t mlen = (l + 7) / 8;
  constexpr size_t pklen = utils::pke_pub_key_len(n, n_bar, lA, Q);
  constexpr size_t sklen = utils::pke_sec_key_len(n, n_bar, Q);
  constexpr size_t ctlen = utils::pke_cipher_text_len(n, m_bar, n_bar, Q);

  std::vector<uint8_t> seedA(lA / 8, 0);
  std::vector<uint8_t> seedSE(lSE / 8, 0);
  std::vector<uint8_t> pkey(pklen, 0);
  std::vector<uint8_t> skey(sklen, 0);
  std::vector<uint8_t> msg(mlen, 0);
  std::vector<uint8_t> enc(ctlen, 0);
  std::vector<uint8_t> dec(mlen, 0);

  std::span<uint8_t, lA / 8> _seedA{ seedA };
  std::span<uint8_t, lSE / 8> _seedSE{ seedSE };
  std::span<uint8_t, pklen> _pkey{ pkey };
  std::span<uint8_t, sklen> _skey{ skey };
  std::span<uint8_t, mlen> _msg{ msg };
  std::span<uint8_t, ctlen> _enc{ enc };
  std::span<uint8_t, mlen> _dec{ dec };

  prng::prng_t prng;

  prng.read(seedA.data(), seedA.size());
  prng.read(seedSE.data(), seedSE.size());
  prng.read(msg.data(), msg.size());

  {
    using namespace pke;

    keygen<n, n_bar, lA, lSE, lχ, Q, B>(_seedA, _seedSE, _pkey, _skey);
    encrypt<n, l, m_bar, n_bar, lA, lSE, lχ, Q, B>(_seedSE, _pkey, _msg, _enc);
    decrypt<n, l, m_bar, n_bar, Q, B>(_skey, _enc, _dec);
  }

  assert(std::ranges::equal(_msg, _dec));
}

}
