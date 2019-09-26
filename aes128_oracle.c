#include <stdio.h>

#include "aes128_oracle.h"

#include "aes128_internal.c"
#include "aes128_oracle_tables.c"

void aes128_oracle_encrypt(const uint8_t in[16],
    uint8_t out[16]) {
  // Copy the input to the state.
  uint8_t state[16] = {
    in[ 0], in[ 1], in[ 2], in[ 3],
    in[ 4], in[ 5], in[ 6], in[ 7],
    in[ 8], in[ 9], in[10], in[11],
    in[12], in[13], in[14], in[15],
  };

  // Perform the necessary number of rounds. The round key is added first.
  // The last round does not perform the MixColumns step.
  for (int r = 0; r < 9; r++) {
    ShiftRows(state);

    // Using T-boxes + Ty(i) Tables (single step):
    for (int j = 0; j < 4; ++j) {
      uint8_t n0, n1, n2, n3;
      uint32_t aa, bb, cc, dd;

      aa = Tyboxes[r][j*4 + 0][state[j*4 + 0]],
      bb = Tyboxes[r][j*4 + 1][state[j*4 + 1]],
      cc = Tyboxes[r][j*4 + 2][state[j*4 + 2]],
      dd = Tyboxes[r][j*4 + 3][state[j*4 + 3]];

      n0 = Xor[r][j*24 +  0][(aa >> 28) & 0xf][(bb >> 28) & 0xf];
      n1 = Xor[r][j*24 +  1][(cc >> 28) & 0xf][(dd >> 28) & 0xf];
      n2 = Xor[r][j*24 +  2][(aa >> 24) & 0xf][(bb >> 24) & 0xf];
      n3 = Xor[r][j*24 +  3][(cc >> 24) & 0xf][(dd >> 24) & 0xf];
      state[j*4 + 0] = (Xor[r][j*24 + 4][n0][n1] << 4) | Xor[r][j*24 + 5][n2][n3];

      n0 = Xor[r][j*24 +  6][(aa >> 20) & 0xf][(bb >> 20) & 0xf];
      n1 = Xor[r][j*24 +  7][(cc >> 20) & 0xf][(dd >> 20) & 0xf];
      n2 = Xor[r][j*24 +  8][(aa >> 16) & 0xf][(bb >> 16) & 0xf];
      n3 = Xor[r][j*24 +  9][(cc >> 16) & 0xf][(dd >> 16) & 0xf];
      state[j*4 + 1] = (Xor[r][j*24 + 10][n0][n1] << 4) | Xor[r][j*24 + 11][n2][n3];

      n0 = Xor[r][j*24 + 12][(aa >> 12) & 0xf][(bb >> 12) & 0xf];
      n1 = Xor[r][j*24 + 13][(cc >> 12) & 0xf][(dd >> 12) & 0xf];
      n2 = Xor[r][j*24 + 14][(aa >>  8) & 0xf][(bb >>  8) & 0xf];
      n3 = Xor[r][j*24 + 15][(cc >>  8) & 0xf][(dd >>  8) & 0xf];
      state[j*4 + 2] = (Xor[r][j*24 + 16][n0][n1] << 4) | Xor[r][j*24 + 17][n2][n3];

      n0 = Xor[r][j*24 + 18][(aa >>  4) & 0xf][(bb >>  4) & 0xf];
      n1 = Xor[r][j*24 + 19][(cc >>  4) & 0xf][(dd >>  4) & 0xf];
      n2 = Xor[r][j*24 + 20][(aa >>  0) & 0xf][(bb >>  0) & 0xf];
      n3 = Xor[r][j*24 + 21][(cc >>  0) & 0xf][(dd >>  0) & 0xf];
      state[j*4 + 3] = (Xor[r][j*24 + 22][n0][n1] << 4) | Xor[r][j*24 + 23][n2][n3];

      aa = MBL[r][j*4 + 0][state[j*4 + 0]];
      bb = MBL[r][j*4 + 1][state[j*4 + 1]];
      cc = MBL[r][j*4 + 2][state[j*4 + 2]];
      dd = MBL[r][j*4 + 3][state[j*4 + 3]];

      n0 = Xor[r][j*24 +  0][(aa >> 28) & 0xf][(bb >> 28) & 0xf];
      n1 = Xor[r][j*24 +  1][(cc >> 28) & 0xf][(dd >> 28) & 0xf];
      n2 = Xor[r][j*24 +  2][(aa >> 24) & 0xf][(bb >> 24) & 0xf];
      n3 = Xor[r][j*24 +  3][(cc >> 24) & 0xf][(dd >> 24) & 0xf];
      state[j*4 + 0] = (Xor[r][j*24 + 4][n0][n1] << 4) | Xor[r][j*24 + 5][n2][n3];

      n0 = Xor[r][j*24 +  6][(aa >> 20) & 0xf][(bb >> 20) & 0xf];
      n1 = Xor[r][j*24 +  7][(cc >> 20) & 0xf][(dd >> 20) & 0xf];
      n2 = Xor[r][j*24 +  8][(aa >> 16) & 0xf][(bb >> 16) & 0xf];
      n3 = Xor[r][j*24 +  9][(cc >> 16) & 0xf][(dd >> 16) & 0xf];
      state[j*4 + 1] = (Xor[r][j*24 + 10][n0][n1] << 4) | Xor[r][j*24 + 11][n2][n3];

      n0 = Xor[r][j*24 + 12][(aa >> 12) & 0xf][(bb >> 12) & 0xf];
      n1 = Xor[r][j*24 + 13][(cc >> 12) & 0xf][(dd >> 12) & 0xf];
      n2 = Xor[r][j*24 + 14][(aa >>  8) & 0xf][(bb >>  8) & 0xf];
      n3 = Xor[r][j*24 + 15][(cc >>  8) & 0xf][(dd >>  8) & 0xf];
      state[j*4 + 2] = (Xor[r][j*24 + 16][n0][n1] << 4) | Xor[r][j*24 + 17][n2][n3];

      n0 = Xor[r][j*24 + 18][(aa >>  4) & 0xf][(bb >>  4) & 0xf];
      n1 = Xor[r][j*24 + 19][(cc >>  4) & 0xf][(dd >>  4) & 0xf];
      n2 = Xor[r][j*24 + 20][(aa >>  0) & 0xf][(bb >>  0) & 0xf];
      n3 = Xor[r][j*24 + 21][(cc >>  0) & 0xf][(dd >>  0) & 0xf];
      state[j*4 + 3] = (Xor[r][j*24 + 22][n0][n1] << 4) | Xor[r][j*24 + 23][n2][n3];
    }
  }

  ShiftRows(state);

  // Using T-boxes:
  for (int i = 0; i < 16; i++)
    out[i] = Tboxes10[i][state[i]];
}

void aes128_oracle_decrypt(const uint8_t in[16],
    uint8_t out[16]) {
  // Copy the input to the state.
  uint8_t state[16] = {
    in[ 0], in[ 1], in[ 2], in[ 3],
    in[ 4], in[ 5], in[ 6], in[ 7],
    in[ 8], in[ 9], in[10], in[11],
    in[12], in[13], in[14], in[15],
  };

  // Using T-boxes:
  for (int i = 0; i < 16; i++)
    state[i] = InvTboxes[9][i][state[i]];

  InvShiftRows(state);
  for (int r = 9; r > 0; r--) {
    // Using InvTy(i) + T-boxes Tables (single step):
    for (int j = 0; j < 4; ++j) {
      uint8_t a = state[j*4 + 0], b = state[j*4 + 1],
              c = state[j*4 + 2], d = state[j*4 + 3];

      uint8_t aa = (InvTy[0][a] >> 24) ^ (InvTy[0][b] >> 16) ^ (InvTy[0][c] >> 8) ^ (InvTy[0][d] >> 0);
      uint8_t bb = (InvTy[1][a] >> 24) ^ (InvTy[1][b] >> 16) ^ (InvTy[1][c] >> 8) ^ (InvTy[1][d] >> 0);
      uint8_t cc = (InvTy[2][a] >> 24) ^ (InvTy[2][b] >> 16) ^ (InvTy[2][c] >> 8) ^ (InvTy[2][d] >> 0);
      uint8_t dd = (InvTy[3][a] >> 24) ^ (InvTy[3][b] >> 16) ^ (InvTy[3][c] >> 8) ^ (InvTy[3][d] >> 0);

      state[j*4 + 0] = InvTboxes[r-1][j*4 + 0][aa];
      state[j*4 + 1] = InvTboxes[r-1][j*4 + 1][bb];
      state[j*4 + 2] = InvTboxes[r-1][j*4 + 2][cc];
      state[j*4 + 3] = InvTboxes[r-1][j*4 + 3][dd];
    }

    InvShiftRows(state);
  }

  // Copy the state to the output array.
  for (int i = 0; i < 16; i++)
    out[i] = state[i];
}
