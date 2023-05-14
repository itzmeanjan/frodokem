#pragma once
#include "pke.hpp"

// Frodo-640 Public Key Encryption
namespace frodo640_pke {

namespace utils = frodo_utils;

// = 9616 -bytes public key
constexpr size_t PUB_KEY_LEN = utils::pke_pub_key_len(640, 8, 128, 1u << 15);

// = 9600 -bytes secret key
constexpr size_t SEC_KEY_LEN = utils::pke_sec_key_len(640, 8, 1u << 15);

// = 9720 -bytes cipher text
constexpr size_t CIPHER_LEN = utils::pke_cipher_text_len(640, 8, 8, 1u << 15);

// Given 16 -bytes seedA ( used for generating matrix A ) and 16 -bytes seedSE (
// used for sampling error matrices ), this routine is used for deterministic
// generation of a Frodo-640 public/ private keypair.
inline void
keygen(std::span<const uint8_t, 16> seedA,
       std::span<const uint8_t, 16> seedSE,
       std::span<uint8_t, 9616> pkey,
       std::span<uint8_t, 9600> skey)
{
  pke::keygen<640, 8, 128, 128, 16, 1u << 15, 2>(seedA, seedSE, pkey, skey);
}

// Given a 16 -bytes seedSE ( used for sampling error matrices ), along with 16
// -bytes message and 9616 -bytes Frodo-640 PKE public key, this routine can be
// used for encrypting the 16 -bytes message as 9720 -bytes cipher text, which
// can only be decrypted by associated Frodo-640 secret key.
inline void
encrypt(std::span<const uint8_t, 16> seed,
        std::span<const uint8_t, 9616> pkey,
        std::span<const uint8_t, 16> msg,
        std::span<uint8_t, 9720> enc)
{
  pke::encrypt<640, 128, 8, 8, 128, 128, 16, 1u << 15, 2>(seed, pkey, msg, enc);
}

// Given a 9720 -bytes cipher text and 9600 -bytes Frodo-640 secret key ( only
// the one whose associated public key was used during encryption, otherwise it
// should decrypt to message m' which doesn't match original encrypted message m
// ), this routine can be used for decrypting cipher text into a 16 -bytes
// message m.
inline void
decrypt(std::span<const uint8_t, 9600> skey,
        std::span<const uint8_t, 9720> enc,
        std::span<uint8_t, 16> msg)
{
  pke::decrypt<640, 128, 8, 8, 1u << 15, 2>(skey, enc, msg);
}

}
