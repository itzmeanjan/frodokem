#include "frodo640_pke.hpp"
#include <algorithm>
#include <cassert>
#include <iostream>
#include <vector>

// Compile it using
//
// g++ -std=c++20 -O3 -march=native -mtune=native -Wall -I include -I
// sha3/include -I subtle/include examples/frodo640_pke.cpp
int
main()
{
  // SeedA, SeedSE byte length
  constexpr size_t SEED_A_LEN = 16;
  constexpr size_t SEED_SE_LEN = 16;

  // To be encrypted message byte length
  constexpr size_t MLEN = 16;

  std::vector<uint8_t> pkey(frodo640_pke::PUB_KEY_LEN, 0);
  std::vector<uint8_t> skey(frodo640_pke::SEC_KEY_LEN, 0);
  std::vector<uint8_t> cipher(frodo640_pke::CIPHER_LEN, 0);
  std::vector<uint8_t> seedA(SEED_A_LEN, 0);
  std::vector<uint8_t> seedSE(SEED_SE_LEN, 0);
  std::vector<uint8_t> msg(MLEN, 0);
  std::vector<uint8_t> decrypted(MLEN, 0);

  prng::prng_t prng;
  prng.read(seedA.data(), seedA.size());
  prng.read(seedSE.data(), seedSE.size());
  prng.read(msg.data(), msg.size());

  frodo640_pke::keygen(seedA.data(), seedSE.data(), pkey.data(), skey.data());
  frodo640_pke::encrypt(seedSE.data(), pkey.data(), msg.data(), cipher.data());
  frodo640_pke::decrypt(skey.data(), cipher.data(), decrypted.data());

  // check if original message m == decrypted message m'
  assert(std::ranges::equal(msg, decrypted));

  {
    using namespace frodo_utils;

    std::cout << "Frodo-640 PKE\n\n";
    std::cout << "SeedA       : " << to_hex(seedA.data(), seedA.size()) << "\n";
    std::cout << "SeedSE      : " << to_hex(seedSE.data(), seedSE.size())
              << "\n";
    std::cout << "Public Key  : " << to_hex(pkey.data(), pkey.size()) << "\n";
    std::cout << "Secret Key  : " << to_hex(skey.data(), skey.size()) << "\n";
    std::cout << "Message     : " << to_hex(msg.data(), msg.size()) << "\n";
    std::cout << "Cipher Text : " << to_hex(cipher.data(), cipher.size())
              << "\n";
    std::cout << "Decrypted   : " << to_hex(decrypted.data(), decrypted.size())
              << "\n";
  }

  return 0;
}
