#include "efrodo1344_kem.hpp"
#include "efrodo640_kem.hpp"
#include "efrodo976_kem.hpp"
#include "frodo640_kem.hpp"
#include "frodo976_kem.hpp"
#include "utils.hpp"
#include <array>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <string_view>

// Test if
//
// - Is Frodo640 KEM implemented correctly ?
// - Is it conformant with the specification ?
//
// using KATs.
TEST(FrodoKEM, Frodo640KEMKAT)
{
  using namespace std::literals;
  namespace utils = frodo_utils;

  const std::string kat_file = "./kats/FrodoKEM640_KAT.txt";
  std::fstream file(kat_file);

  while (true) {
    std::string s;

    if (!std::getline(file, s).eof()) {
      std::string seedSE;
      std::string z;
      std::string pkey;
      std::string skey;
      std::string μ;
      std::string salt;
      std::string ct;
      std::string ss;

      std::getline(file, seedSE);
      std::getline(file, z);
      std::getline(file, pkey);
      std::getline(file, skey);
      std::getline(file, μ);
      std::getline(file, salt);
      std::getline(file, ct);
      std::getline(file, ss);

      auto _s = std::string_view(s);
      auto __s = _s.substr(_s.find("="sv) + 2, _s.size());
      auto ___s = utils::from_hex<frodo640_kem::len_sec / 8>(__s);

      auto _seedSE = std::string_view(seedSE);
      auto __seedSE = _seedSE.substr(_seedSE.find("="sv) + 2, _seedSE.size());
      auto ___seedSE = utils::from_hex<frodo640_kem::len_SE / 8>(__seedSE);

      auto _z = std::string_view(z);
      auto __z = _z.substr(_z.find("="sv) + 2, _z.size());
      auto ___z = utils::from_hex<frodo640_kem::len_A / 8>(__z);

      auto _pkey = std::string_view(pkey);
      auto __pkey = _pkey.substr(_pkey.find("="sv) + 2, _pkey.size());
      auto ___pkey = utils::from_hex<frodo640_kem::PUB_KEY_LEN>(__pkey);

      auto _skey = std::string_view(skey);
      auto __skey = _skey.substr(_skey.find("="sv) + 2, _skey.size());
      auto ___skey = utils::from_hex<frodo640_kem::SEC_KEY_LEN>(__skey);

      auto _μ = std::string_view(μ);
      auto __μ = _μ.substr(_μ.find("="sv) + 2, _μ.size());
      auto ___μ = utils::from_hex<frodo640_kem::len_sec / 8>(__μ);

      auto _salt = std::string_view(salt);
      auto __salt = _salt.substr(_salt.find("="sv) + 2, _salt.size());
      auto ___salt = utils::from_hex<frodo640_kem::len_salt / 8>(__salt);

      auto _ct = std::string_view(ct);
      auto __ct = _ct.substr(_ct.find("="sv) + 2, _ct.size());
      auto ___ct = utils::from_hex<frodo640_kem::CIPHER_LEN>(__ct);

      auto _ss = std::string_view(ss);
      auto __ss = _ss.substr(_ss.find("="sv) + 2, _ss.size());
      auto ___ss = utils::from_hex<frodo640_kem::len_sec / 8>(__ss);

      std::array<uint8_t, frodo640_kem::PUB_KEY_LEN> pubkey{};
      std::array<uint8_t, frodo640_kem::SEC_KEY_LEN> seckey{};
      std::array<uint8_t, frodo640_kem::CIPHER_LEN> ctxt{};
      std::array<uint8_t, frodo640_kem::len_sec / 8> shrd_sec0{};
      std::array<uint8_t, frodo640_kem::len_sec / 8> shrd_sec1{};

      frodo640_kem::keygen(___s, ___seedSE, ___z, pubkey, seckey);
      frodo640_kem::encaps(___μ, ___salt, pubkey, ctxt, shrd_sec0);
      frodo640_kem::decaps(seckey, ctxt, shrd_sec1);

      EXPECT_TRUE(std::ranges::equal(___pkey, pubkey));
      EXPECT_TRUE(std::ranges::equal(___skey, seckey));
      EXPECT_TRUE(std::ranges::equal(___ct, ctxt));
      EXPECT_TRUE(std::ranges::equal(___ss, shrd_sec0));
      EXPECT_TRUE(std::ranges::equal(shrd_sec0, shrd_sec1));

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}

// Test if
//
// - Is Frodo976 KEM implemented correctly ?
// - Is it conformant with the specification ?
//
// using KATs.
TEST(FrodoKEM, Frodo976KEMKAT)
{
  using namespace std::literals;
  namespace utils = frodo_utils;

  const std::string kat_file = "./kats/FrodoKEM976_KAT.txt";
  std::fstream file(kat_file);

  while (true) {
    std::string s;

    if (!std::getline(file, s).eof()) {
      std::string seedSE;
      std::string z;
      std::string pkey;
      std::string skey;
      std::string μ;
      std::string salt;
      std::string ct;
      std::string ss;

      std::getline(file, seedSE);
      std::getline(file, z);
      std::getline(file, pkey);
      std::getline(file, skey);
      std::getline(file, μ);
      std::getline(file, salt);
      std::getline(file, ct);
      std::getline(file, ss);

      auto _s = std::string_view(s);
      auto __s = _s.substr(_s.find("="sv) + 2, _s.size());
      auto ___s = utils::from_hex<frodo976_kem::len_sec / 8>(__s);

      auto _seedSE = std::string_view(seedSE);
      auto __seedSE = _seedSE.substr(_seedSE.find("="sv) + 2, _seedSE.size());
      auto ___seedSE = utils::from_hex<frodo976_kem::len_SE / 8>(__seedSE);

      auto _z = std::string_view(z);
      auto __z = _z.substr(_z.find("="sv) + 2, _z.size());
      auto ___z = utils::from_hex<frodo976_kem::len_A / 8>(__z);

      auto _pkey = std::string_view(pkey);
      auto __pkey = _pkey.substr(_pkey.find("="sv) + 2, _pkey.size());
      auto ___pkey = utils::from_hex<frodo976_kem::PUB_KEY_LEN>(__pkey);

      auto _skey = std::string_view(skey);
      auto __skey = _skey.substr(_skey.find("="sv) + 2, _skey.size());
      auto ___skey = utils::from_hex<frodo976_kem::SEC_KEY_LEN>(__skey);

      auto _μ = std::string_view(μ);
      auto __μ = _μ.substr(_μ.find("="sv) + 2, _μ.size());
      auto ___μ = utils::from_hex<frodo976_kem::len_sec / 8>(__μ);

      auto _salt = std::string_view(salt);
      auto __salt = _salt.substr(_salt.find("="sv) + 2, _salt.size());
      auto ___salt = utils::from_hex<frodo976_kem::len_salt / 8>(__salt);

      auto _ct = std::string_view(ct);
      auto __ct = _ct.substr(_ct.find("="sv) + 2, _ct.size());
      auto ___ct = utils::from_hex<frodo976_kem::CIPHER_LEN>(__ct);

      auto _ss = std::string_view(ss);
      auto __ss = _ss.substr(_ss.find("="sv) + 2, _ss.size());
      auto ___ss = utils::from_hex<frodo976_kem::len_sec / 8>(__ss);

      std::array<uint8_t, frodo976_kem::PUB_KEY_LEN> pubkey{};
      std::array<uint8_t, frodo976_kem::SEC_KEY_LEN> seckey{};
      std::array<uint8_t, frodo976_kem::CIPHER_LEN> ctxt{};
      std::array<uint8_t, frodo976_kem::len_sec / 8> shrd_sec0{};
      std::array<uint8_t, frodo976_kem::len_sec / 8> shrd_sec1{};

      frodo976_kem::keygen(___s, ___seedSE, ___z, pubkey, seckey);
      frodo976_kem::encaps(___μ, ___salt, pubkey, ctxt, shrd_sec0);
      frodo976_kem::decaps(seckey, ctxt, shrd_sec1);

      EXPECT_TRUE(std::ranges::equal(___pkey, pubkey));
      EXPECT_TRUE(std::ranges::equal(___skey, seckey));
      EXPECT_TRUE(std::ranges::equal(___ct, ctxt));
      EXPECT_TRUE(std::ranges::equal(___ss, shrd_sec0));
      EXPECT_TRUE(std::ranges::equal(shrd_sec0, shrd_sec1));

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}

// Test if
//
// - Is eFrodo640 KEM implemented correctly ?
// - Is it conformant with the specification ?
//
// using KATs.
TEST(FrodoKEM, eFrodo640KEMKAT)
{
  using namespace std::literals;
  namespace utils = frodo_utils;

  const std::string kat_file = "./kats/eFrodoKEM640_KAT.txt";
  std::fstream file(kat_file);

  while (true) {
    std::string s;

    if (!std::getline(file, s).eof()) {
      std::string seedSE;
      std::string z;
      std::string pkey;
      std::string skey;
      std::string μ;
      std::string ct;
      std::string ss;

      std::getline(file, seedSE);
      std::getline(file, z);
      std::getline(file, pkey);
      std::getline(file, skey);
      std::getline(file, μ);
      std::getline(file, ct);
      std::getline(file, ss);

      auto _s = std::string_view(s);
      auto __s = _s.substr(_s.find("="sv) + 2, _s.size());
      auto ___s = utils::from_hex<16>(__s);

      auto _seedSE = std::string_view(seedSE);
      auto __seedSE = _seedSE.substr(_seedSE.find("="sv) + 2, _seedSE.size());
      auto ___seedSE = utils::from_hex<16>(__seedSE);

      auto _z = std::string_view(z);
      auto __z = _z.substr(_z.find("="sv) + 2, _z.size());
      auto ___z = utils::from_hex<16>(__z);

      auto _pkey = std::string_view(pkey);
      auto __pkey = _pkey.substr(_pkey.find("="sv) + 2, _pkey.size());
      auto ___pkey = utils::from_hex<efrodo640_kem::PUB_KEY_LEN>(__pkey);

      auto _skey = std::string_view(skey);
      auto __skey = _skey.substr(_skey.find("="sv) + 2, _skey.size());
      auto ___skey = utils::from_hex<efrodo640_kem::SEC_KEY_LEN>(__skey);

      auto _μ = std::string_view(μ);
      auto __μ = _μ.substr(_μ.find("="sv) + 2, _μ.size());
      auto ___μ = utils::from_hex<16>(__μ);

      auto _ct = std::string_view(ct);
      auto __ct = _ct.substr(_ct.find("="sv) + 2, _ct.size());
      auto ___ct = utils::from_hex<efrodo640_kem::CIPHER_LEN>(__ct);

      auto _ss = std::string_view(ss);
      auto __ss = _ss.substr(_ss.find("="sv) + 2, _ss.size());
      auto ___ss = utils::from_hex<16>(__ss);

      std::array<uint8_t, efrodo640_kem::PUB_KEY_LEN> pubkey{};
      std::array<uint8_t, efrodo640_kem::SEC_KEY_LEN> seckey{};
      std::array<uint8_t, efrodo640_kem::CIPHER_LEN> ctxt{};
      std::array<uint8_t, 16> shrd_sec0{};
      std::array<uint8_t, 16> shrd_sec1{};

      efrodo640_kem::keygen(___s, ___seedSE, ___z, pubkey, seckey);
      efrodo640_kem::encaps(___μ, pubkey, ctxt, shrd_sec0);
      efrodo640_kem::decaps(seckey, ctxt, shrd_sec1);

      EXPECT_TRUE(std::ranges::equal(___pkey, pubkey));
      EXPECT_TRUE(std::ranges::equal(___skey, seckey));
      EXPECT_TRUE(std::ranges::equal(___ct, ctxt));
      EXPECT_TRUE(std::ranges::equal(___ss, shrd_sec0));
      EXPECT_TRUE(std::ranges::equal(shrd_sec0, shrd_sec1));

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}

// Test if
//
// - Is eFrodo976 KEM implemented correctly ?
// - Is it conformant with the specification ?
//
// using KATs.
TEST(FrodoKEM, eFrodo976KEMKAT)
{
  using namespace std::literals;
  namespace utils = frodo_utils;

  const std::string kat_file = "./kats/eFrodoKEM976_KAT.txt";
  std::fstream file(kat_file);

  while (true) {
    std::string s;

    if (!std::getline(file, s).eof()) {
      std::string seedSE;
      std::string z;
      std::string pkey;
      std::string skey;
      std::string μ;
      std::string ct;
      std::string ss;

      std::getline(file, seedSE);
      std::getline(file, z);
      std::getline(file, pkey);
      std::getline(file, skey);
      std::getline(file, μ);
      std::getline(file, ct);
      std::getline(file, ss);

      auto _s = std::string_view(s);
      auto __s = _s.substr(_s.find("="sv) + 2, _s.size());
      auto ___s = utils::from_hex<24>(__s);

      auto _seedSE = std::string_view(seedSE);
      auto __seedSE = _seedSE.substr(_seedSE.find("="sv) + 2, _seedSE.size());
      auto ___seedSE = utils::from_hex<24>(__seedSE);

      auto _z = std::string_view(z);
      auto __z = _z.substr(_z.find("="sv) + 2, _z.size());
      auto ___z = utils::from_hex<16>(__z);

      auto _pkey = std::string_view(pkey);
      auto __pkey = _pkey.substr(_pkey.find("="sv) + 2, _pkey.size());
      auto ___pkey = utils::from_hex<efrodo976_kem::PUB_KEY_LEN>(__pkey);

      auto _skey = std::string_view(skey);
      auto __skey = _skey.substr(_skey.find("="sv) + 2, _skey.size());
      auto ___skey = utils::from_hex<efrodo976_kem::SEC_KEY_LEN>(__skey);

      auto _μ = std::string_view(μ);
      auto __μ = _μ.substr(_μ.find("="sv) + 2, _μ.size());
      auto ___μ = utils::from_hex<24>(__μ);

      auto _ct = std::string_view(ct);
      auto __ct = _ct.substr(_ct.find("="sv) + 2, _ct.size());
      auto ___ct = utils::from_hex<efrodo976_kem::CIPHER_LEN>(__ct);

      auto _ss = std::string_view(ss);
      auto __ss = _ss.substr(_ss.find("="sv) + 2, _ss.size());
      auto ___ss = utils::from_hex<24>(__ss);

      std::array<uint8_t, efrodo976_kem::PUB_KEY_LEN> pubkey{};
      std::array<uint8_t, efrodo976_kem::SEC_KEY_LEN> seckey{};
      std::array<uint8_t, efrodo976_kem::CIPHER_LEN> ctxt{};
      std::array<uint8_t, 24> shrd_sec0{};
      std::array<uint8_t, 24> shrd_sec1{};

      efrodo976_kem::keygen(___s, ___seedSE, ___z, pubkey, seckey);
      efrodo976_kem::encaps(___μ, pubkey, ctxt, shrd_sec0);
      efrodo976_kem::decaps(seckey, ctxt, shrd_sec1);

      EXPECT_TRUE(std::ranges::equal(___pkey, pubkey));
      EXPECT_TRUE(std::ranges::equal(___skey, seckey));
      EXPECT_TRUE(std::ranges::equal(___ct, ctxt));
      EXPECT_TRUE(std::ranges::equal(___ss, shrd_sec0));
      EXPECT_TRUE(std::ranges::equal(shrd_sec0, shrd_sec1));

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}

// Test if
//
// - Is eFrodo1344 KEM implemented correctly ?
// - Is it conformant with the specification ?
//
// using KATs.
TEST(FrodoKEM, eFrodo1344KEMKAT)
{
  using namespace std::literals;
  namespace utils = frodo_utils;

  const std::string kat_file = "./kats/eFrodoKEM1344_KAT.txt";
  std::fstream file(kat_file);

  while (true) {
    std::string s;

    if (!std::getline(file, s).eof()) {
      std::string seedSE;
      std::string z;
      std::string pkey;
      std::string skey;
      std::string μ;
      std::string ct;
      std::string ss;

      std::getline(file, seedSE);
      std::getline(file, z);
      std::getline(file, pkey);
      std::getline(file, skey);
      std::getline(file, μ);
      std::getline(file, ct);
      std::getline(file, ss);

      auto _s = std::string_view(s);
      auto __s = _s.substr(_s.find("="sv) + 2, _s.size());
      auto ___s = utils::from_hex<32>(__s);

      auto _seedSE = std::string_view(seedSE);
      auto __seedSE = _seedSE.substr(_seedSE.find("="sv) + 2, _seedSE.size());
      auto ___seedSE = utils::from_hex<32>(__seedSE);

      auto _z = std::string_view(z);
      auto __z = _z.substr(_z.find("="sv) + 2, _z.size());
      auto ___z = utils::from_hex<16>(__z);

      auto _pkey = std::string_view(pkey);
      auto __pkey = _pkey.substr(_pkey.find("="sv) + 2, _pkey.size());
      auto ___pkey = utils::from_hex<efrodo1344_kem::PUB_KEY_LEN>(__pkey);

      auto _skey = std::string_view(skey);
      auto __skey = _skey.substr(_skey.find("="sv) + 2, _skey.size());
      auto ___skey = utils::from_hex<efrodo1344_kem::SEC_KEY_LEN>(__skey);

      auto _μ = std::string_view(μ);
      auto __μ = _μ.substr(_μ.find("="sv) + 2, _μ.size());
      auto ___μ = utils::from_hex<32>(__μ);

      auto _ct = std::string_view(ct);
      auto __ct = _ct.substr(_ct.find("="sv) + 2, _ct.size());
      auto ___ct = utils::from_hex<efrodo1344_kem::CIPHER_LEN>(__ct);

      auto _ss = std::string_view(ss);
      auto __ss = _ss.substr(_ss.find("="sv) + 2, _ss.size());
      auto ___ss = utils::from_hex<32>(__ss);

      std::array<uint8_t, efrodo1344_kem::PUB_KEY_LEN> pubkey{};
      std::array<uint8_t, efrodo1344_kem::SEC_KEY_LEN> seckey{};
      std::array<uint8_t, efrodo1344_kem::CIPHER_LEN> ctxt{};
      std::array<uint8_t, 32> shrd_sec0{};
      std::array<uint8_t, 32> shrd_sec1{};

      efrodo1344_kem::keygen(___s, ___seedSE, ___z, pubkey, seckey);
      efrodo1344_kem::encaps(___μ, pubkey, ctxt, shrd_sec0);
      efrodo1344_kem::decaps(seckey, ctxt, shrd_sec1);

      EXPECT_TRUE(std::ranges::equal(___pkey, pubkey));
      EXPECT_TRUE(std::ranges::equal(___skey, seckey));
      EXPECT_TRUE(std::ranges::equal(___ct, ctxt));
      EXPECT_TRUE(std::ranges::equal(___ss, shrd_sec0));
      EXPECT_TRUE(std::ranges::equal(shrd_sec0, shrd_sec1));

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}
