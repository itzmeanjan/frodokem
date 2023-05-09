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
keygen(const uint8_t* const __restrict seedA,  // 16 -bytes
       const uint8_t* const __restrict seedSE, // 16 -bytes
       uint8_t* const __restrict pkey,         // 9616 -bytes
       uint8_t* const __restrict skey          // 9600 -bytes
)
{
  pke::keygen<640, 8, 128, 128, 16, 1u << 15, 2>(seedA, seedSE, pkey, skey);
}

// Given a 16 -bytes seedSE ( used for sampling error matrices ), along with 16
// -bytes message and 9616 -bytes Frodo-640 PKE public key, this routine can be
// used for encrypting the 16 -bytes message as 9720 -bytes cipher text, which
// can only be decrypted by associated Frodo-640 secret key.
inline void
encrypt(const uint8_t* const __restrict seed, // 16 -bytes
        const uint8_t* const __restrict pkey, // 9616 -bytes
        const uint8_t* const __restrict msg,  // 16 -bytes
        uint8_t* const __restrict enc         // 9720 -bytes
)
{
  pke::encrypt<640, 128, 8, 8, 128, 128, 16, 1u << 15, 2>(seed, pkey, msg, enc);
}

// Given a 9720 -bytes cipher text and 9600 -bytes Frodo-640 secret key ( only
// the one whose associated public key was used during encryption, otherwise it
// should decrypt to message m' which doesn't match original encrypted message m
// ), this routine can be used for decrypting cipher text into a 16 -bytes
// message m.
inline void
decrypt(const uint8_t* const __restrict skey, // 9600 -bytes
        const uint8_t* const __restrict enc,  // 9720 -bytes
        uint8_t* const __restrict msg         // 16 -bytes
)
{
  pke::decrypt<640, 128, 8, 8, 1u << 15, 2>(skey, enc, msg);
}

}
