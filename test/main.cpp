#include "test/test_frodo.hpp"
#include <iostream>

int
main()
{
  test_frodo::test_zq_encode_decode<15, 2>();
  test_frodo::test_zq_encode_decode<16, 3>();
  test_frodo::test_zq_encode_decode<16, 4>();
  test_frodo::test_lemma_2_18<15, 2>();
  test_frodo::test_lemma_2_18<16, 3>();
  test_frodo::test_lemma_2_18<16, 4>();
  std::cout << "[test] Encoding/ decoding of Zq elements\n";

  test_frodo::test_matrix_encode_decode<8, 8, 15, 2>();
  test_frodo::test_matrix_encode_decode<8, 8, 15, 3>();
  test_frodo::test_matrix_encode_decode<8, 8, 15, 4>();
  test_frodo::test_matrix_encode_decode<8, 8, 16, 2>();
  test_frodo::test_matrix_encode_decode<8, 8, 16, 3>();
  test_frodo::test_matrix_encode_decode<8, 8, 16, 4>();
  std::cout << "[test] Encoding/ decoding of matrix over Zq\n";

  test_frodo::test_matrix_pack_unpack<640, 8, 15>();
  test_frodo::test_matrix_pack_unpack<8, 640, 15>();
  test_frodo::test_matrix_pack_unpack<976, 8, 16>();
  test_frodo::test_matrix_pack_unpack<8, 976, 16>();
  test_frodo::test_matrix_pack_unpack<1344, 8, 16>();
  test_frodo::test_matrix_pack_unpack<8, 1344, 16>();
  test_frodo::test_matrix_pack_unpack<8, 8, 15>();
  test_frodo::test_matrix_pack_unpack<8, 8, 16>();
  std::cout << "[test] Packing/ unpacking of matrix over Zq\n";

  test_frodo::test_matrix_transpose<8, 640, 15>();
  test_frodo::test_matrix_transpose<8, 976, 16>();
  test_frodo::test_matrix_transpose<8, 1344, 16>();

  test_frodo::test_matrix_add_sub<8, 640, 15>();
  test_frodo::test_matrix_add_sub<8, 976, 16>();
  test_frodo::test_matrix_add_sub<8, 1344, 16>();
  test_frodo::test_matrix_add_sub<8, 8, 15>();
  test_frodo::test_matrix_add_sub<8, 8, 16>();
  std::cout << "[test] Operations on matrices over Zq\n";

  {
    using namespace test_frodo;

    test_kem<640, 8, 8, 128, 128, 128, 128, 128, 128, 128, 128, 16, 15, 2>();
    test_kem<976, 8, 8, 128, 192, 192, 128, 192, 192, 192, 192, 16, 16, 3>();
    test_kem<1344, 8, 8, 128, 256, 256, 128, 256, 256, 256, 256, 16, 16, 4>();
    std::cout << "[test] Frodo Key Encapsulation Mechanism\n";
  }

  test_frodo::test_frodo640_kem_kat();
  test_frodo::test_frodo976_kem_kat();
  test_frodo::test_frodo1344_kem_kat();
  std::cout << "[test] Frodo KEM Known Answer Tests\n";

  return 0;
}
