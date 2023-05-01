#include "test/test_frodo.hpp"
#include <iostream>

int
main()
{
  test_frodo::test_zq_encode_decode<1u << 15, 2>();
  test_frodo::test_zq_encode_decode<1u << 15, 3>();
  test_frodo::test_zq_encode_decode<1u << 15, 4>();
  test_frodo::test_zq_encode_decode<1u << 16, 2>();
  test_frodo::test_zq_encode_decode<1u << 16, 3>();
  test_frodo::test_zq_encode_decode<1u << 16, 4>();
  std::cout << "[test] Encoding/ decoding of Zq elements\n";

  test_frodo::test_matrix_encode_decode<8, 8, 1u << 15, 2>();
  test_frodo::test_matrix_encode_decode<8, 8, 1u << 15, 3>();
  test_frodo::test_matrix_encode_decode<8, 8, 1u << 15, 4>();
  test_frodo::test_matrix_encode_decode<8, 8, 1u << 16, 2>();
  test_frodo::test_matrix_encode_decode<8, 8, 1u << 16, 3>();
  test_frodo::test_matrix_encode_decode<8, 8, 1u << 16, 4>();
  std::cout << "[test] Encoding/ decoding of matrix over Zq\n";

  test_frodo::test_matrix_pack_unpack<8, 8, 1u << 15>();
  test_frodo::test_matrix_pack_unpack<8, 8, 1u << 16>();
  std::cout << "[test] Packing/ unpacking of matrix over Zq\n";

  return 0;
}
