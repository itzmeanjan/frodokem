#pragma once
#include "kem.hpp"

// Frodo-976 Key Encapsulation Mechanism
namespace frodo976_kem {

// See column 1, 3 of table 4 of FrodoKEM specification.
constexpr size_t D = 16;
constexpr size_t Q = 1u << D;
constexpr size_t n = 976;
constexpr size_t m̄ = 8;
constexpr size_t n̄ = 8;
constexpr size_t B = 3;
constexpr size_t lA = 128;   // = len_seed_A
constexpr size_t lz = 128;   // = len_z
constexpr size_t lμ = 192;   // = len_μ = l
constexpr size_t lSE = 192;  // = len_seed_SE
constexpr size_t ls = 192;   // = len_s
constexpr size_t lk = 192;   // = len_k
constexpr size_t lpkh = 192; // = len_pkh
constexpr size_t lss = 192;  // = len_ss
constexpr size_t lχ = 16;    // = len_χ

// = 15632 -bytes public key
constexpr auto PUB_KEY_LEN = kem::kem_pub_key_len(n, n̄, lA, Q);

// = 31296 -bytes secret key
constexpr auto SEC_KEY_LEN = kem::kem_sec_key_len(n, n̄, ls, lA, lpkh, Q);

// Given 24 -bytes seed s ( secret part of private key ), 24 -bytes seed seedSE
// ( used for sampling error matrices ) and 16 -bytes seed z ( used for deriving
// pseudo-random seed seedA, which is used for generating matrix A ), this
// routine can be used for deterministic generation of a Frodo-976 public/
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

}