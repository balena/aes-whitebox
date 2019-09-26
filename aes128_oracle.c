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
      uint8_t a = state[j*4 + 0], b = state[j*4 + 1],
              c = state[j*4 + 2], d = state[j*4 + 3];

      uint32_t aa = Tyboxes[r][j*4 + 0][a],
               bb = Tyboxes[r][j*4 + 1][b],
               cc = Tyboxes[r][j*4 + 2][c],
               dd = Tyboxes[r][j*4 + 3][d];

      uint32_t o = aa ^ bb ^ cc ^ dd;

      aa = MBL[r][j*4 + 0][(o >> 24) & 0xff];
      bb = MBL[r][j*4 + 1][(o >> 16) & 0xff];
      cc = MBL[r][j*4 + 2][(o >>  8) & 0xff];
      dd = MBL[r][j*4 + 3][(o >>  0) & 0xff];

      o = aa ^ bb ^ cc ^ dd;

      state[j*4 + 0] = (o >> 24) & 0xff;
      state[j*4 + 1] = (o >> 16) & 0xff;
      state[j*4 + 2] = (o >>  8) & 0xff;
      state[j*4 + 3] = (o >>  0) & 0xff;
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
