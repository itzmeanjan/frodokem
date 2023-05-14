#pragma once
#include "pke.hpp"

// Frodo-976 Public Key Encryption
namespace frodo976_pke {

namespace utils = frodo_utils;

// = 15632 -bytes public key
constexpr size_t PUB_KEY_LEN = utils::pke_pub_key_len(976, 8, 128, 1u << 16);

// = 15616 -bytes secret key
constexpr size_t SEC_KEY_LEN = utils::pke_sec_key_len(976, 8, 1u << 16);

// = 15744 -bytes cipher text
constexpr size_t CIPHER_LEN = utils::pke_cipher_text_len(976, 8, 8, 1u << 16);

// Given 16 -bytes seedA ( used for generating matrix A ) and 24 -bytes seedSE (
// used for sampling error matrices ), this routine is used for deterministic
// generation of a Frodo-976 public/ private keypair.
inline void
keygen(std::span<const uint8_t, 16> seedA,
       std::span<const uint8_t, 24> seedSE,
       std::span<uint8_t, 15632> pkey,
       std::span<uint8_t, 15616> skey)
{
  pke::keygen<976, 8, 128, 192, 16, 1u << 16, 3>(seedA, seedSE, pkey, skey);
}

// Given a 24 -bytes seedSE ( used for sampling error matrices ), along with 24
// -bytes message and 15632 -bytes Frodo-976 PKE public key, this routine can be
// used for encrypting the 24 -bytes message as 15744 -bytes cipher text, which
// can only be decrypted by associated Frodo-976 secret key.
inline void
encrypt(std::span<const uint8_t, 24> seed,
        std::span<const uint8_t, 15632> pkey,
        std::span<const uint8_t, 24> msg,
        std::span<uint8_t, 15744> enc)
{
  pke::encrypt<976, 192, 8, 8, 128, 192, 16, 1u << 16, 3>(seed, pkey, msg, enc);
}

// Given a 15744 -bytes cipher text and 15616 -bytes Frodo-976 secret key ( only
// the one whose associated public key was used during encryption, otherwise it
// should decrypt to message m' which doesn't match original encrypted message m
// ), this routine can be used for decrypting cipher text into a 24 -bytes
// message m.
inline void
decrypt(std::span<const uint8_t, 15616> skey,
        std::span<const uint8_t, 15744> enc,
        std::span<uint8_t, 24> msg)
{
  pke::decrypt<976, 192, 8, 8, 1u << 16, 3>(skey, enc, msg);
}

}
