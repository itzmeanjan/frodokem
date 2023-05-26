#pragma once
#include "kem.hpp"

// Frodo-976 Key Encapsulation Mechanism
namespace frodo976_kem {

// See table A.1, A.2 of FrodoKEM specification.
constexpr size_t D = 16;
constexpr size_t n = 976;
constexpr size_t n̄ = 8;
constexpr size_t B = 3;
constexpr size_t len_A = 128;
constexpr size_t len_sec = 192;
constexpr size_t len_SE = 384;
constexpr size_t len_salt = 384;

// = 15632 -bytes public key
constexpr auto PUB_KEY_LEN = kem::kem_pub_key_len(n, n̄, len_A, D);

// = 31296 -bytes secret key
constexpr auto SEC_KEY_LEN = kem::kem_sec_key_len(n, n̄, len_sec, len_A, D);

// = 15792 -bytes cipher text
constexpr auto CIPHER_LEN = kem::kem_cipher_text_len(n, n̄, len_salt, D);

// Given 24 -bytes seed s ( secret part of private key ), 48 -bytes seed seedSE
// ( used for sampling error matrices ) and 16 -bytes seed z ( used for deriving
// pseudo-random seed seedA, which is used for generating matrix A ), this
// routine can be used for deterministic generation of a Frodo-976 public/
// private keypair, following algorithm described in section 8.1 of FrodoKEM
// specification.
inline void
keygen(std::span<const uint8_t, len_sec / 8> s,
       std::span<const uint8_t, len_SE / 8> seedSE,
       std::span<const uint8_t, len_A / 8> z,
       std::span<uint8_t, PUB_KEY_LEN> pkey,
       std::span<uint8_t, SEC_KEY_LEN> skey)
{
  kem::keygen<n, n̄, len_sec, len_SE, len_A, B, D>(s, seedSE, z, pkey, skey);
}

// Given 24 -bytes key μ ( which is actually encrypted using underlying PKE
// scheme ), 48 -bytes salt and a Frodo-976 KEM public key, this routine can be
// used for computing a cipher text ( which can only be decrypted using
// corresponding Frodo-976 KEM private key ) and a 24 -bytes shared
// secret,following algorithm described in section 8.2 of FrodoKEM
// specification.
inline void
encaps(std::span<const uint8_t, len_sec / 8> μ,
       std::span<const uint8_t, len_salt / 8> salt,
       std::span<const uint8_t, PUB_KEY_LEN> pkey,
       std::span<uint8_t, CIPHER_LEN> enc,
       std::span<uint8_t, len_sec / 8> ss)
{
  kem::encaps<n, n̄, len_sec, len_SE, len_A, len_salt, B, D>(
    μ, salt, pkey, enc, ss);
}

// Given a Frodo-976 KEM secret key, which is associated with the public key,
// using which the cipher text was computed and the cipher text as input, this
// routine can be used for decrypting the cipher text, recovering 24 -bytes
// shared secret, following algorithm described in section 8.3 of FrodoKEM
// specification.
inline void
decaps(std::span<const uint8_t, SEC_KEY_LEN> skey,
       std::span<const uint8_t, CIPHER_LEN> enc,
       std::span<uint8_t, len_sec / 8> ss)
{
  kem::decaps<n, n̄, len_sec, len_SE, len_A, len_salt, B, D>(skey, enc, ss);
}

}