#include "efrodo640_kem.hpp"
#include "prng.hpp"
#include <algorithm>
#include <cassert>
#include <iostream>
#include <span>
#include <vector>

// Compile it using
//
// g++ -std=c++20 -O3 -march=native -mtune=native -Wall -I include -I
// sha3/include -I subtle/include examples/efrodo640_kem.cpp
int
main()
{
  constexpr size_t S_LEN = efrodo640_kem::len_sec / 8;
  constexpr size_t SEED_SE_LEN = efrodo640_kem::len_SE / 8;
  constexpr size_t Z_LEN = efrodo640_kem::len_A / 8;
  constexpr size_t μ_LEN = efrodo640_kem::len_sec / 8;
  constexpr size_t SS_LEN = efrodo640_kem::len_sec / 8; // shared secret

  std::vector<uint8_t> s(S_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> z(Z_LEN, 0);
  std::vector<uint8_t> pkey(efrodo640_kem::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(efrodo640_kem::SEC_KEY_LEN, 0);
  std::vector<uint8_t> μ(μ_LEN, 0);
  std::vector<uint8_t> ss0(SS_LEN, 0);
  std::vector<uint8_t> cipher(efrodo640_kem::CIPHER_LEN, 0);
  std::vector<uint8_t> ss1(SS_LEN, 0);

  std::span<uint8_t, S_LEN> _s{ s };
  std::span<uint8_t, SEED_SE_LEN> _seedSE{ seedSE };
  std::span<uint8_t, Z_LEN> _z{ z };
  std::span<uint8_t, efrodo640_kem::PUB_KEY_LEN> _pkey{ pkey };
  std::span<uint8_t, efrodo640_kem::SEC_KEY_LEN> _skey{ skey };
  std::span<uint8_t, μ_LEN> _μ{ μ };
  std::span<uint8_t, SS_LEN> _ss0{ ss0 };
  std::span<uint8_t, efrodo640_kem::CIPHER_LEN> _cipher{ cipher };
  std::span<uint8_t, SS_LEN> _ss1{ ss1 };

  prng::prng_t prng;

  prng.read(_s);
  prng.read(_seedSE);
  prng.read(_z);
  prng.read(_μ);

  efrodo640_kem::keygen(_s, _seedSE, _z, _pkey, _skey);
  efrodo640_kem::encaps(_μ, _pkey, _cipher, _ss0);
  efrodo640_kem::decaps(_skey, _cipher, _ss1);

  // check if both parties arrived at same shared secret or not
  assert(std::ranges::equal(_ss0, _ss1));

  {
    using namespace frodo_utils;

    std::cout << "eFrodo-640 KEM\n\n";
    std::cout << "Public Key    : " << to_hex(_pkey) << "\n";
    std::cout << "Secret Key    : " << to_hex(_skey) << "\n";
    std::cout << "Cipher Text   : " << to_hex(_cipher) << "\n";
    std::cout << "Shared Secret : " << to_hex(_ss0) << "\n";
  }

  return 0;
}
