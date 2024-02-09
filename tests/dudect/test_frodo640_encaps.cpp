#include "frodo640_kem.hpp"
#include "prng.hpp"
#include <array>
#include <cstdint>
#include <cstdio>

#define DUDECT_IMPLEMENTATION
#define DUDECT_VISIBLITY_STATIC
#include "dudect.h"

constexpr size_t μ_BYTE_LEN = frodo640_kem::len_sec / 8;
constexpr size_t SALT_BYTE_LEN = frodo640_kem::len_salt / 8;
constexpr size_t CHUNK_BYTE_LEN = μ_BYTE_LEN + SALT_BYTE_LEN + frodo640_kem::PUB_KEY_LEN;

constexpr size_t DOFF0 = 0;
constexpr size_t DOFF1 = DOFF0 + μ_BYTE_LEN;
constexpr size_t DOFF2 = DOFF1 + SALT_BYTE_LEN;
constexpr size_t DOFF3 = DOFF2 + frodo640_kem::PUB_KEY_LEN;

uint8_t
do_one_computation(uint8_t* const data)
{
  constexpr size_t DOFF0 = 0;
  constexpr size_t DOFF1 = DOFF0 + μ_BYTE_LEN;
  constexpr size_t DOFF2 = DOFF1 + SALT_BYTE_LEN;
  constexpr size_t DOFF3 = DOFF2 + frodo640_kem::PUB_KEY_LEN;

  auto μ = std::span<const uint8_t, DOFF1 - DOFF0>(data + DOFF0, DOFF1 - DOFF0);
  auto salt = std::span<const uint8_t, DOFF2 - DOFF1>(data + DOFF1, DOFF2 - DOFF1);
  auto pkey = std::span<const uint8_t, DOFF3 - DOFF2>(data + DOFF2, DOFF3 - DOFF2);

  std::array<uint8_t, frodo640_kem::CIPHER_LEN> enc{};
  std::array<uint8_t, frodo640_kem::len_sec / 8> ss{};

  uint8_t ret_val = 0;

  frodo640_kem::encaps(μ, salt, pkey, enc, ss);
  ret_val ^= (enc[0] ^ enc[enc.size() - 1]) ^ (ss[0] ^ ss[ss.size() - 1]);

  return ret_val;
}

void
prepare_inputs(dudect_config_t* const c, uint8_t* const input_data, uint8_t* const classes)
{
  randombytes(input_data, c->number_measurements * c->chunk_size);

  for (size_t i = 0; i < c->number_measurements; i++) {
    classes[i] = randombit();
    if (classes[i] == 0) {
      // Generate a valid remote public key
      const size_t chunk_begin = i * c->chunk_size;
      uint8_t* chunk = input_data + chunk_begin;

      std::array<uint8_t, frodo640_kem::len_sec / 8> s{};
      std::array<uint8_t, frodo640_kem::len_SE / 8> seedSE{};
      std::array<uint8_t, frodo640_kem::len_A / 8> z{};
      auto pkey = std::span<uint8_t, DOFF3 - DOFF2>(chunk + DOFF2, DOFF3 - DOFF2);
      std::array<uint8_t, frodo640_kem::SEC_KEY_LEN> skey{};

      prng::prng_t prng;

      prng.read(s);
      prng.read(seedSE);
      prng.read(z);

      frodo640_kem::keygen(s, seedSE, z, pkey, skey);
    } else {
      // Keep the remote public key random, probably invalid too !
    }
  }
}

dudect_state_t
test_frodo640_encaps()
{
  constexpr size_t chunk_size = CHUNK_BYTE_LEN;
  constexpr size_t number_measurements = 1e5;

  dudect_config_t config = {
    chunk_size,
    number_measurements,
  };
  dudect_ctx_t ctx;
  dudect_init(&ctx, &config);

  dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
  while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
    state = dudect_main(&ctx);
  }

  dudect_free(&ctx);

  printf("Detected timing leakage in \"%s\", defined in file \"%s\"\n", __func__, __FILE_NAME__);
  return state;
}

int
main()
{
  if (test_frodo640_encaps() != DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
