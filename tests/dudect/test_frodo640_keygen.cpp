#include "frodo640_kem.hpp"
#include <array>
#include <cstdint>
#include <cstdio>

#define DUDECT_IMPLEMENTATION
#define DUDECT_VISIBLITY_STATIC
#include "dudect.h"

constexpr size_t S_BYTE_LEN = frodo640_kem::len_sec / 8;
constexpr size_t SEED_SE_BYTE_LEN = frodo640_kem::len_SE / 8;
constexpr size_t Z_BYTE_LEN = frodo640_kem::len_A / 8;
constexpr size_t CHUNK_BYTE_LEN = S_BYTE_LEN + SEED_SE_BYTE_LEN + Z_BYTE_LEN;

uint8_t
do_one_computation(uint8_t* const data)
{
  constexpr size_t doff0 = 0;
  constexpr size_t doff1 = doff0 + S_BYTE_LEN;
  constexpr size_t doff2 = doff1 + SEED_SE_BYTE_LEN;
  constexpr size_t doff3 = doff2 + Z_BYTE_LEN;

  auto s = std::span<const uint8_t, doff1 - doff0>(data + doff0, doff1 - doff0);
  auto seedSE =
    std::span<const uint8_t, doff2 - doff1>(data + doff1, doff2 - doff1);
  auto z = std::span<const uint8_t, doff3 - doff2>(data + doff2, doff3 - doff2);

  std::array<uint8_t, frodo640_kem::PUB_KEY_LEN> pkey{};
  std::array<uint8_t, frodo640_kem::SEC_KEY_LEN> skey{};

  uint8_t ret_val = 0;

  frodo640_kem::keygen(s, seedSE, z, pkey, skey);
  ret_val ^=
    (pkey[0] ^ pkey[pkey.size() - 1]) ^ (skey[0] ^ skey[skey.size() - 1]);

  return ret_val;
}

void
prepare_inputs(dudect_config_t* const c,
               uint8_t* const input_data,
               uint8_t* const classes)
{
  randombytes(input_data, c->number_measurements * c->chunk_size);

  for (size_t i = 0; i < c->number_measurements; i++) {
    classes[i] = randombit();
    if (classes[i] == 0) {
      std::memset(input_data + i * c->chunk_size, 0x00, c->chunk_size);
    }
  }
}

dudect_state_t
test_frodo640_keygen()
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

  printf("Detected timing leakage in \"%s\", defined in file \"%s\"\n",
         __func__,
         __FILE_NAME__);
  return state;
}

int
main()
{
  if (test_frodo640_keygen() != DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
