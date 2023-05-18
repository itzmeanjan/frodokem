#pragma once
#include "kem.hpp"

// Frodo-1344 Key Encapsulation Mechanism
namespace frodo1344_kem {

// See column 1, 4 of table 4 of FrodoKEM specification.
constexpr size_t D = 16;
constexpr size_t Q = 1u << D;
constexpr size_t n = 1344;
constexpr size_t m̄ = 8;
constexpr size_t n̄ = 8;
constexpr size_t B = 4;
constexpr size_t lA = 128;   // = len_seed_A
constexpr size_t lz = 128;   // = len_z
constexpr size_t lμ = 256;   // = len_μ = l
constexpr size_t lSE = 256;  // = len_seed_SE
constexpr size_t ls = 256;   // = len_s
constexpr size_t lk = 256;   // = len_k
constexpr size_t lpkh = 256; // = len_pkh
constexpr size_t lss = 256;  // = len_ss
constexpr size_t lχ = 16;    // = len_χ

// = 21520 -bytes public key
constexpr auto PUB_KEY_LEN = kem::kem_pub_key_len(n, n̄, lA, Q);

// = 43088 -bytes secret key
constexpr auto SEC_KEY_LEN = kem::kem_sec_key_len(n, n̄, ls, lA, lpkh, Q);

// = 21632 -bytes cipher text
constexpr auto CIPHER_LEN = kem::kem_cipher_text_len(n, m̄, n̄, Q);

// Given 32 -bytes seed s ( secret part of private key ), 32 -bytes seed seedSE
// ( used for sampling error matrices ) and 16 -bytes seed z ( used for deriving
// pseudo-random seed seedA, which is used for generating matrix A ), this
// routine can be used for deterministic generation of a Frodo-1344 public/
// private keypair, following algorithm 12 of FrodoKEM specification.
inline void
keygen(std::span<const uint8_t, ls / 8> s,
       std::span<const uint8_t, lSE / 8> seedSE,
       std::span<const uint8_t, lz / 8> z,
       std::span<uint8_t, PUB_KEY_LEN> pkey,
       std::span<uint8_t, SEC_KEY_LEN> skey)
{
  kem::keygen<n, n̄, lA, lSE, ls, lz, lpkh, lχ, Q, B>(s, seedSE, z, pkey, skey);
}

// Given a 32 -bytes key μ ( which is actually encrypted using underlying PKE
// scheme ) and a Frodo-1344 KEM public key, this routine can be used for
// computing a cipher text ( which can only be decrypted using corresponding
// Frodo-1344 KEM private key ) and a 32 -bytes shared secret.
inline void
encaps(std::span<const uint8_t, (lμ + 7) / 8> μ,
       std::span<const uint8_t, PUB_KEY_LEN> pkey,
       std::span<uint8_t, CIPHER_LEN> enc,
       std::span<uint8_t, (lss + 7) / 8> ss)
{
  kem::encaps<n, m̄, n̄, lA, lSE, lss, lk, lμ, lpkh, lχ, Q, B>(μ, pkey, enc, ss);
}

// Given Frodo-1344 KEM secret key, which is associated with the public key,
// using which the cipher text was computed and the cipher text as input, this
// routine can be used for decrypting the cipher text, recovering 32 -bytes
// shared secret.
inline void
decaps(std::span<const uint8_t, SEC_KEY_LEN> skey,
       std::span<const uint8_t, CIPHER_LEN> enc,
       std::span<uint8_t, (lss + 7) / 8> ss)
{
  kem::decaps<n, m̄, n̄, lA, lSE, ls, lss, lk, lμ, lpkh, lχ, Q, B>(skey, enc, ss);
}

}
