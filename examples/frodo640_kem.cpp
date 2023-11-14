#include "frodo640_kem.hpp"
#include "prng.hpp"
#include <algorithm>
#include <cassert>
#include <iostream>
#include <span>
#include <vector>

// Compile it using
//
// g++ -std=c++20 -O3 -march=native -Wall -I include -I
// sha3/include -I subtle/include examples/frodo640_kem.cpp
int
main()
{
  constexpr size_t S_LEN = frodo640_kem::len_sec / 8;
  constexpr size_t SEED_SE_LEN = frodo640_kem::len_SE / 8;
  constexpr size_t Z_LEN = frodo640_kem::len_A / 8;
  constexpr size_t μ_LEN = frodo640_kem::len_sec / 8;
  constexpr size_t SALT_LEN = frodo640_kem::len_salt / 8;
  constexpr size_t SS_LEN = frodo640_kem::len_sec / 8; // shared secret

  std::vector<uint8_t> s(S_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> z(Z_LEN, 0);
  std::vector<uint8_t> pkey(frodo640_kem::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo640_kem::SEC_KEY_LEN, 0);
  std::vector<uint8_t> μ(μ_LEN, 0);
  std::vector<uint8_t> salt(SALT_LEN, 0);
  std::vector<uint8_t> ss0(SS_LEN, 0);
  std::vector<uint8_t> cipher(frodo640_kem::CIPHER_LEN, 0);
  std::vector<uint8_t> ss1(SS_LEN, 0);

  std::span<uint8_t, S_LEN> _s{ s };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, Z_LEN> _z{ z };
  std::span<uint8_t, frodo640_kem::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, frodo640_kem::SEC_KEY_LEN> _skey{ skey };
  std::span<uint8_t, μ_LEN> _μ{ μ };
  std::span<uint8_t, SALT_LEN> _salt{ salt };
  std::span<uint8_t, SS_LEN> _ss0{ ss0 };
  std::span<uint8_t, frodo640_kem::CIPHER_LEN> _cipher{ cipher };
  std::span<uint8_t, SS_LEN> _ss1{ ss1 };

  prng::prng_t prng;

  prng.read(_s);
  prng.read(_seedSE);
  prng.read(_z);
  prng.read(_μ);
  prng.read(_salt);

  frodo640_kem::keygen(_s, _seedSE, _z, _pkey, _skey);
  frodo640_kem::encaps(_μ, _salt, _pkey, _cipher, _ss0);
  frodo640_kem::decaps(_skey, _cipher, _ss1);

  // check if both parties arrived at same shared secret or not
  assert(std::ranges::equal(_ss0, _ss1));

  std::cout << "Frodo-640 KEM\n\n";
  std::cout << "Public Key    : " << frodo_utils::to_hex(_pkey) << "\n";
  std::cout << "Secret Key    : " << frodo_utils::to_hex(_skey) << "\n";
  std::cout << "Cipher Text   : " << frodo_utils::to_hex(_cipher) << "\n";
  std::cout << "Shared Secret : " << frodo_utils::to_hex(_ss0) << "\n";

  return 0;
}
