#include "test/test_frodo.hpp"
#include "zq.hpp"
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

  return 0;
}
