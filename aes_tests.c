// Copyright 2019 AES WBC Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "aunit.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <math.h>
#include <string.h>

#include "aes.h"
#include "aes_whitebox.h"


static void err_quit(const char *fmt, ...) {
  va_list ap;
  char buf[1024];

  va_start(ap, fmt);
  vsprintf(buf, fmt, ap);
  strcat(buf, "\n");
  fputs(buf, stderr);
  fflush(stderr);
  va_end(ap);

  exit(1);
}

static void read_hex(const char *in, uint8_t* v, size_t size, const char* param_name) {
  if (strlen(in) != size << 1) {
    err_quit("Invalid param %s (got %d, expected %d)",
        param_name, strlen(in), size << 1);
  }
  for (size_t i = 0; i < size; i++) {
    sscanf(in + i * 2, "%2hhx", v + i);
  }
}

void syntax(const char* program_name) {
  err_quit("Syntax: %s <cfb|ofb|ctr>"
      " <hex-plain>"
      " <hex-ir-or-nonce>"
      " <hex-cipher>", program_name);
}

au_main

{
  uint8_t plain[4*16], iv_or_nonce[16], cipher[4*16], output[4*16];

  void (*encrypt)(const uint8_t iv[16], const uint8_t* m,
      size_t len, uint8_t* c) = NULL;
  void (*decrypt)(const uint8_t iv[16], const uint8_t* m,
      size_t len, uint8_t* c) = NULL;

  read_hex(argv[2], plain, 4*16, "plain");
  read_hex(argv[3], iv_or_nonce, 16, "iv-or-nonce");
  read_hex(argv[4], cipher, 4*16, "cipher");

  if (argc != 5) {
    syntax(argv[0]);
  } else if (strcmp(argv[1], "cfb") == 0) {
    encrypt = &aes_whitebox_encrypt_cfb;
    decrypt = &aes_whitebox_decrypt_cfb;
  } else if (strcmp(argv[1], "ofb") == 0) {
    encrypt = &aes_whitebox_encrypt_ofb;
    decrypt = &aes_whitebox_decrypt_ofb;
  } else if (strcmp(argv[1], "ctr") == 0) {
    encrypt = &aes_whitebox_encrypt_ctr;
    decrypt = &aes_whitebox_decrypt_ctr;
  } else {
    syntax(argv[0]);
  }

  (*encrypt)(iv_or_nonce, plain, sizeof(plain), output);
  au_eq("Encrypt, vector #1", memcmp(output, cipher, sizeof(cipher)), 0);
  (*decrypt)(iv_or_nonce, cipher, sizeof(cipher), output);
  au_eq("Decrypt, vector #1", memcmp(output, plain, sizeof(plain)), 0);

  (*encrypt)(iv_or_nonce, plain, 7, output);
  au_eq("Encrypt, vector #2", memcmp(output, cipher, 7), 0);
  (*decrypt)(iv_or_nonce, cipher, 7, output);
  au_eq("Decrypt, vector #2", memcmp(output, plain, 7), 0);
}

au_endmain
