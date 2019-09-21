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

/*
  aes_table_protect(Tboxes, Ty, InvTboxes, InvTy);
  aes_table_encrypt(plain, output, Tboxes, Ty);
  au_eq("Set 1, vector#  0/enc/tab", memcmp(output, cipher, sizeof(cipher)), 0);
  aes_table_decrypt(cipher, output, InvTboxes, InvTy);
  au_eq("Set 1, vector#  0/dec/tab", memcmp(output, plain, sizeof(plain)), 0);
 */
}

au_endmain
