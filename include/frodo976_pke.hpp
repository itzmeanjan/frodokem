#pragma once
#include "pke.hpp"

// Frodo-976 Public Key Encryption
namespace frodo640_pke {

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
keygen(const uint8_t* const __restrict seedA,  // 16 -bytes
       const uint8_t* const __restrict seedSE, // 24 -bytes
       uint8_t* const __restrict pkey,         // 15632 -bytes
       uint8_t* const __restrict skey          // 15616 -bytes
)
{
  pke::keygen<976, 8, 128, 192, 16, 1u << 16, 3>(seedA, seedSE, pkey, skey);
}

// Given a 24 -bytes seedSE ( used for sampling error matrices ), along with 24
// -bytes message and 15632 -bytes Frodo-976 PKE public key, this routine can be
// used for encrypting the 24 -bytes message as 15744 -bytes cipher text, which
// can only be decrypted by associated Frodo-976 secret key.
inline void
encrypt(const uint8_t* const __restrict seed, // 24 -bytes
        const uint8_t* const __restrict pkey, // 15632 -bytes
        const uint8_t* const __restrict msg,  // 24 -bytes
        uint8_t* const __restrict enc         // 15744 -bytes
)
{
  pke::encrypt<976, 192, 8, 8, 128, 192, 16, 1u << 16, 3>(seed, pkey, msg, enc);
}

// Given a 15744 -bytes cipher text and 15616 -bytes Frodo-976 secret key ( only
// the one whose associated public key was used during encryption, otherwise it
// should decrypt to message m' which doesn't match original encrypted message m
// ), this routine can be used for decrypting cipher text into a 24 -bytes
// message m.
inline void
decrypt(const uint8_t* const __restrict skey, // 15616 -bytes
        const uint8_t* const __restrict enc,  // 15744 -bytes
        uint8_t* const __restrict msg         // 24 -bytes
)
{
  pke::decrypt<976, 192, 8, 8, 1u << 16, 3>(skey, enc, msg);
}

}
