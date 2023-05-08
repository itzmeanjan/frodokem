#include "test/test_frodo.hpp"
#include <iostream>

int
main()
{
  test_frodo::test_zq_encode_decode<1u << 15, 2>();
  test_frodo::test_zq_encode_decode<1u << 16, 3>();
  test_frodo::test_zq_encode_decode<1u << 16, 4>();
  test_frodo::test_lemma_2_18<1u << 15, 2>();
  test_frodo::test_lemma_2_18<1u << 16, 3>();
  test_frodo::test_lemma_2_18<1u << 16, 4>();
  std::cout << "[test] Encoding/ decoding of Zq elements\n";

  test_frodo::test_matrix_encode_decode<8, 8, 1u << 15, 2>();
  test_frodo::test_matrix_encode_decode<8, 8, 1u << 15, 3>();
  test_frodo::test_matrix_encode_decode<8, 8, 1u << 15, 4>();
  test_frodo::test_matrix_encode_decode<8, 8, 1u << 16, 2>();
  test_frodo::test_matrix_encode_decode<8, 8, 1u << 16, 3>();
  test_frodo::test_matrix_encode_decode<8, 8, 1u << 16, 4>();
  std::cout << "[test] Encoding/ decoding of matrix over Zq\n";

  test_frodo::test_matrix_pack_unpack<640, 8, 1u << 15>();
  test_frodo::test_matrix_pack_unpack<8, 640, 1u << 15>();
  test_frodo::test_matrix_pack_unpack<976, 8, 1u << 16>();
  test_frodo::test_matrix_pack_unpack<8, 976, 1u << 16>();
  test_frodo::test_matrix_pack_unpack<1344, 8, 1u << 16>();
  test_frodo::test_matrix_pack_unpack<8, 1344, 1u << 16>();
  test_frodo::test_matrix_pack_unpack<8, 8, 1u << 15>();
  test_frodo::test_matrix_pack_unpack<8, 8, 1u << 16>();
  std::cout << "[test] Packing/ unpacking of matrix over Zq\n";

  test_frodo::test_matrix_transpose<8, 640, 1u << 15>();
  test_frodo::test_matrix_transpose<8, 976, 1u << 16>();
  test_frodo::test_matrix_transpose<8, 1344, 1u << 16>();

  test_frodo::test_matrix_add_sub<8, 640, 1u << 15>();
  test_frodo::test_matrix_add_sub<8, 976, 1u << 16>();
  test_frodo::test_matrix_add_sub<8, 1344, 1u << 16>();
  test_frodo::test_matrix_add_sub<8, 8, 1u << 15>();
  test_frodo::test_matrix_add_sub<8, 8, 1u << 16>();
  std::cout << "[test] Operations on matrices over Zq\n";

  test_frodo::test_pke<640, 128, 8, 8, 128, 128, 16, 1u << 15, 2>();
  test_frodo::test_pke<976, 192, 8, 8, 128, 192, 16, 1u << 16, 3>();
  test_frodo::test_pke<1344, 256, 8, 8, 128, 256, 16, 1u << 16, 4>();
  std::cout << "[test] Frodo Public Key Encryption\n";

  return 0;
}
