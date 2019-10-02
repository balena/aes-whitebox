// Copyright 2019 AES WBC Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "aes_whitebox.h"

#include "aes_whitebox_tables.cc"

namespace {

void ShiftRows(uint8_t state[16]) {
  constexpr int shifts[16] = {
     0,  5, 10, 15,
     4,  9, 14,  3,
     8, 13,  2,  7,
    12,  1,  6, 11,
  };

  const uint8_t in[16] = {
    state[ 0], state[ 1], state[ 2], state[ 3],
    state[ 4], state[ 5], state[ 6], state[ 7],
    state[ 8], state[ 9], state[10], state[11],
    state[12], state[13], state[14], state[15],
  };

  for (int i = 0; i < 16; i++)
    state[i] = in[shifts[i]];
}

void Cipher(uint8_t in[16]) {
  // Perform the necessary number of rounds. The round key is added first.
  // The last round does not perform the MixColumns step.
  for (int r = 0; r < Nr-1; r++) {
    ShiftRows(in);

    // Using T-boxes + Ty(i) Tables (single step):
    for (int j = 0; j < 4; ++j) {
      uint8_t n0, n1, n2, n3;
      uint32_t aa, bb, cc, dd;

      aa = Tyboxes[r][j*4 + 0][in[j*4 + 0]],
      bb = Tyboxes[r][j*4 + 1][in[j*4 + 1]],
      cc = Tyboxes[r][j*4 + 2][in[j*4 + 2]],
      dd = Tyboxes[r][j*4 + 3][in[j*4 + 3]];

      n0 = Xor[r][j*24 +  0][(aa >> 28) & 0xf][(bb >> 28) & 0xf];
      n1 = Xor[r][j*24 +  1][(cc >> 28) & 0xf][(dd >> 28) & 0xf];
      n2 = Xor[r][j*24 +  2][(aa >> 24) & 0xf][(bb >> 24) & 0xf];
      n3 = Xor[r][j*24 +  3][(cc >> 24) & 0xf][(dd >> 24) & 0xf];
      in[j*4 + 0] = (Xor[r][j*24 + 4][n0][n1] << 4) | Xor[r][j*24 + 5][n2][n3];

      n0 = Xor[r][j*24 +  6][(aa >> 20) & 0xf][(bb >> 20) & 0xf];
      n1 = Xor[r][j*24 +  7][(cc >> 20) & 0xf][(dd >> 20) & 0xf];
      n2 = Xor[r][j*24 +  8][(aa >> 16) & 0xf][(bb >> 16) & 0xf];
      n3 = Xor[r][j*24 +  9][(cc >> 16) & 0xf][(dd >> 16) & 0xf];
      in[j*4 + 1] = (Xor[r][j*24 + 10][n0][n1] << 4) | Xor[r][j*24 + 11][n2][n3];

      n0 = Xor[r][j*24 + 12][(aa >> 12) & 0xf][(bb >> 12) & 0xf];
      n1 = Xor[r][j*24 + 13][(cc >> 12) & 0xf][(dd >> 12) & 0xf];
      n2 = Xor[r][j*24 + 14][(aa >>  8) & 0xf][(bb >>  8) & 0xf];
      n3 = Xor[r][j*24 + 15][(cc >>  8) & 0xf][(dd >>  8) & 0xf];
      in[j*4 + 2] = (Xor[r][j*24 + 16][n0][n1] << 4) | Xor[r][j*24 + 17][n2][n3];

      n0 = Xor[r][j*24 + 18][(aa >>  4) & 0xf][(bb >>  4) & 0xf];
      n1 = Xor[r][j*24 + 19][(cc >>  4) & 0xf][(dd >>  4) & 0xf];
      n2 = Xor[r][j*24 + 20][(aa >>  0) & 0xf][(bb >>  0) & 0xf];
      n3 = Xor[r][j*24 + 21][(cc >>  0) & 0xf][(dd >>  0) & 0xf];
      in[j*4 + 3] = (Xor[r][j*24 + 22][n0][n1] << 4) | Xor[r][j*24 + 23][n2][n3];

      aa = MBL[r][j*4 + 0][in[j*4 + 0]];
      bb = MBL[r][j*4 + 1][in[j*4 + 1]];
      cc = MBL[r][j*4 + 2][in[j*4 + 2]];
      dd = MBL[r][j*4 + 3][in[j*4 + 3]];

      n0 = Xor[r][j*24 +  0][(aa >> 28) & 0xf][(bb >> 28) & 0xf];
      n1 = Xor[r][j*24 +  1][(cc >> 28) & 0xf][(dd >> 28) & 0xf];
      n2 = Xor[r][j*24 +  2][(aa >> 24) & 0xf][(bb >> 24) & 0xf];
      n3 = Xor[r][j*24 +  3][(cc >> 24) & 0xf][(dd >> 24) & 0xf];
      in[j*4 + 0] = (Xor[r][j*24 + 4][n0][n1] << 4) | Xor[r][j*24 + 5][n2][n3];

      n0 = Xor[r][j*24 +  6][(aa >> 20) & 0xf][(bb >> 20) & 0xf];
      n1 = Xor[r][j*24 +  7][(cc >> 20) & 0xf][(dd >> 20) & 0xf];
      n2 = Xor[r][j*24 +  8][(aa >> 16) & 0xf][(bb >> 16) & 0xf];
      n3 = Xor[r][j*24 +  9][(cc >> 16) & 0xf][(dd >> 16) & 0xf];
      in[j*4 + 1] = (Xor[r][j*24 + 10][n0][n1] << 4) | Xor[r][j*24 + 11][n2][n3];

      n0 = Xor[r][j*24 + 12][(aa >> 12) & 0xf][(bb >> 12) & 0xf];
      n1 = Xor[r][j*24 + 13][(cc >> 12) & 0xf][(dd >> 12) & 0xf];
      n2 = Xor[r][j*24 + 14][(aa >>  8) & 0xf][(bb >>  8) & 0xf];
      n3 = Xor[r][j*24 + 15][(cc >>  8) & 0xf][(dd >>  8) & 0xf];
      in[j*4 + 2] = (Xor[r][j*24 + 16][n0][n1] << 4) | Xor[r][j*24 + 17][n2][n3];

      n0 = Xor[r][j*24 + 18][(aa >>  4) & 0xf][(bb >>  4) & 0xf];
      n1 = Xor[r][j*24 + 19][(cc >>  4) & 0xf][(dd >>  4) & 0xf];
      n2 = Xor[r][j*24 + 20][(aa >>  0) & 0xf][(bb >>  0) & 0xf];
      n3 = Xor[r][j*24 + 21][(cc >>  0) & 0xf][(dd >>  0) & 0xf];
      in[j*4 + 3] = (Xor[r][j*24 + 22][n0][n1] << 4) | Xor[r][j*24 + 23][n2][n3];
    }
  }

  ShiftRows(in);

  // Using T-boxes:
  for (int i = 0; i < 16; i++)
    in[i] = TboxesLast[i][in[i]];
}

}  // namespace

extern "C" {

void aes_whitebox_encrypt_cfb(const uint8_t iv[16], const uint8_t* m,
    size_t len, uint8_t* c) {
  uint8_t cfb_blk[16];

  for (int i = 0; i < 16; i++)
    cfb_blk[i] = iv[i];

  for (size_t i = 0; i < len; i++) {
    if ((i & 0xf) == 0)
      Cipher(cfb_blk);
    cfb_blk[i & 0xf] ^= m[i];
    c[i] = cfb_blk[i & 0xf];
  }
}

void aes_whitebox_decrypt_cfb(const uint8_t iv[16], const uint8_t* c,
    size_t len, uint8_t* m) {
  uint8_t cfb_blk[16];

  for (int i = 0; i < 16; i++)
    cfb_blk[i] = iv[i];

  for (size_t i = 0; i < len; i++) {
    if ((i & 0xf) == 0)
      Cipher(cfb_blk);
    m[i] = cfb_blk[i & 0xf] ^ c[i];
    cfb_blk[i & 0xf] = c[i];
  }
}

void aes_whitebox_encrypt_ofb(const uint8_t iv[16], const uint8_t* m,
    size_t len, uint8_t* c) {
  uint8_t cfb_blk[16];

  for (int i = 0; i < 16; i++)
    cfb_blk[i] = iv[i];

  for (size_t i = 0; i < len; i++) {
    if ((i & 0xf) == 0)
      Cipher(cfb_blk);
    c[i] = m[i] ^ cfb_blk[i & 0xf];
  }
}

void aes_whitebox_decrypt_ofb(const uint8_t iv[16], const uint8_t* c,
    size_t len, uint8_t* m) {
  aes_whitebox_encrypt_ofb(iv, c, len, m);
}

void aes_whitebox_encrypt_ctr(const uint8_t nonce[16], const uint8_t* m,
    size_t len, uint8_t* c) {
  uint8_t counter[16], buf[16];

  for (int i = 0; i < 16; i++)
    counter[i] = nonce[i];

  for (size_t i = 0; i < len; i++) {
    if ((i & 0xf) == 0) {
      for (int j = 0; j < 16; j++)
        buf[j] = counter[j];
      Cipher(buf);
      for (int j = 15; j >= 0; j--) {
        counter[j]++;
        if (counter[j])
          break;
      }
    }
    c[i] = m[i] ^ buf[i & 0xf];
  }
}

void aes_whitebox_decrypt_ctr(const uint8_t nonce[16], const uint8_t* c,
    size_t len, uint8_t* m) {
  aes_whitebox_encrypt_ctr(nonce, c, len, m);
}

}  // extern "C"
