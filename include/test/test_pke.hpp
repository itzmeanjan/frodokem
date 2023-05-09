#pragma once
#include "pke.hpp"
#include "prng.hpp"
#include "utils.hpp"
#include <cassert>

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

  constexpr size_t mlen = l / 8;
  constexpr size_t pklen = utils::pke_pub_key_len(n, n_bar, lA, Q);
  constexpr size_t sklen = utils::pke_sec_key_len(n, n_bar, Q);
  constexpr size_t ctlen = utils::pke_cipher_text_len(n, m_bar, n_bar, Q);

  auto seedA = static_cast<uint8_t*>(std::malloc(lA / 8));
  auto seedSE = static_cast<uint8_t*>(std::malloc(lSE / 8));
  auto pkey = static_cast<uint8_t*>(std::malloc(pklen));
  auto skey = static_cast<uint8_t*>(std::malloc(sklen));
  auto msg = static_cast<uint8_t*>(std::malloc(mlen));
  auto cipher = static_cast<uint8_t*>(std::malloc(ctlen));
  auto decrypted = static_cast<uint8_t*>(std::malloc(mlen));

  prng::prng_t prng;

  prng.read(seedA, lA / 8);
  prng.read(seedSE, lSE / 8);
  prng.read(msg, mlen);

  {
    using namespace pke;

    keygen<n, n_bar, lA, lSE, lχ, Q, B>(seedA, seedSE, pkey, skey);
    encrypt<n, l, m_bar, n_bar, lA, lSE, lχ, Q, B>(seedSE, pkey, msg, cipher);
    decrypt<n, l, m_bar, n_bar, Q, B>(skey, cipher, decrypted);
  }

  for (size_t i = 0; i < mlen; i++) {
    assert(msg[i] == decrypted[i]);
  }

  std::free(seedA);
  std::free(seedSE);
  std::free(pkey);
  std::free(skey);
  std::free(msg);
  std::free(cipher);
  std::free(decrypted);
}

}
