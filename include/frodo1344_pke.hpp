#pragma once
#include "pke.hpp"

// Frodo-1344 Public Key Encryption
namespace frodo1344_pke {

namespace utils = frodo_utils;

// = 21520 -bytes public key
constexpr size_t PUB_KEY_LEN = utils::pke_pub_key_len(1344, 8, 128, 1u << 16);

// = 21504 -bytes secret key
constexpr size_t SEC_KEY_LEN = utils::pke_sec_key_len(1344, 8, 1u << 16);

// = 21632 -bytes cipher text
constexpr size_t CIPHER_LEN = utils::pke_cipher_text_len(1344, 8, 8, 1u << 16);

// Given 16 -bytes seedA ( used for generating matrix A ) and 32 -bytes seedSE (
// used for sampling error matrices ), this routine is used for deterministic
// generation of a Frodo-1344 public/ private keypair.
inline void
keygen(std::span<const uint8_t, 16> seedA,
       std::span<const uint8_t, 32> seedSE,
       std::span<uint8_t, 21520> pkey,
       std::span<uint8_t, 21504> skey)
{
  pke::keygen<1344, 8, 128, 256, 16, 1u << 16, 4>(seedA, seedSE, pkey, skey);
}

// Given a 32 -bytes seedSE ( used for sampling error matrices ), along with 32
// -bytes message and 21520 -bytes Frodo-1344 PKE public key, this routine can
// be used for encrypting the 32 -bytes message as 21632 -bytes cipher text,
// which can only be decrypted by associated Frodo-1344 secret key.
inline void
encrypt(std::span<const uint8_t, 32> seed,
        std::span<const uint8_t, 21520> pkey,
        std::span<const uint8_t, 32> msg,
        std::span<uint8_t, 21632> enc)
{
  pke::encrypt<1344, 256, 8, 8, 128, 256, 16, 1 << 16, 4>(seed, pkey, msg, enc);
}

// Given a 21632 -bytes cipher text and 21504 -bytes Frodo-1344 secret key (
// only the one whose associated public key was used during encryption,
// otherwise it should decrypt to message m' which doesn't match original
// encrypted message m ), this routine can be used for decrypting cipher text
// into a 32 -bytes message m.
inline void
decrypt(std::span<const uint8_t, 21504> skey,
        std::span<const uint8_t, 21632> enc,
        std::span<uint8_t, 32> msg)
{
  pke::decrypt<1344, 256, 8, 8, 1u << 16, 4>(skey, enc, msg);
}

}
