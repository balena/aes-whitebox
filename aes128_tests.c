#include "aunit.h"

#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <string.h>

#include "aes128.h"
#include "aes128_oracle.h"

au_main

{ // full encryption test
  const uint8_t key[16] = {
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  const uint8_t plain[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  const uint8_t cipher[16] = {
    0x0e, 0xdd, 0x33, 0xd3, 0xc6, 0x21, 0xe5, 0x46,
    0x45, 0x5b, 0xd8, 0xba, 0x14, 0x18, 0xbe, 0xc8
  };
  uint32_t roundKey[44];
  uint8_t output[16];

  aes128_expand_keys(key, roundKey);
  aes128_encrypt(plain, output, roundKey);
  au_eq("Set 1, vector#  0/enc/ref", memcmp(output, cipher, sizeof(cipher)), 0);
  aes128_decrypt(cipher, output, roundKey);
  au_eq("Set 1, vector#  0/dec/ref", memcmp(output, plain, sizeof(plain)), 0);

  aes128_oracle_encrypt(plain, output);
  au_eq("Set 1, vector#  0/enc/tab", memcmp(output, cipher, sizeof(cipher)), 0);
  aes128_oracle_decrypt(cipher, output);
  au_eq("Set 1, vector#  0/dec/tab", memcmp(output, plain, sizeof(plain)), 0);
}

#if 0
// In order to test this, we need to change the embedded key to
// 000102030405060708090a0b0c0d0e0f (as specified in FIPS-197).
{
  const uint8_t key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };
  const uint8_t plain[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };
  const uint8_t cipher[16] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
  };

  uint32_t roundKey[44];
  uint8_t output[16];

  aes128_expand_keys(key, roundKey);
  aes128_encrypt(plain, output, roundKey);
  au_eq("Set 2, vector#  1/enc/ref", memcmp(output, cipher, sizeof(cipher)), 0);
  aes128_decrypt(cipher, output, roundKey);
  au_eq("Set 2, vector#  1/dec/ref", memcmp(output, plain, sizeof(plain)), 0);

  aes128_oracle_encrypt(plain, output);
  au_eq("Set 2, vector#  1/enc/tab", memcmp(output, cipher, sizeof(cipher)), 0);
  aes128_oracle_decrypt(cipher, output);
  au_eq("Set 2, vector#  1/dec/tab", memcmp(output, plain, sizeof(plain)), 0);
}
#endif

au_endmain
