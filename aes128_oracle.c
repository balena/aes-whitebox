#include "aes128_oracle.h"

#include "aes128_internal.c"

#include "aes128_oracle_tables.c"

void aes128_oracle_encrypt(const uint8_t in[16],
    uint8_t out[16]) {
  uint8_t state[4][4];

  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
      state[j][i] = in[i*4 + j];

  // Perform the necessary number of rounds. The round key is added first.
  // The last round does not perform the MixColumns step.
  for (int r = 0; r < 9; r++) {
    ShiftRows(state);

    // Using T-boxes + Ty(i) Tables (single step):
    for (int j = 0; j < 4; ++j) {
      uint8_t a = state[0][j], b = state[1][j],
              c = state[2][j], d = state[3][j];

      uint8_t a0 = Tyboxes[r][0][j][a][0], b0 = Tyboxes[r][0][j][b][1], c0 = Tyboxes[r][0][j][c][2], d0 = Tyboxes[r][0][j][d][3],
              a1 = Tyboxes[r][1][j][a][0], b1 = Tyboxes[r][1][j][b][1], c1 = Tyboxes[r][1][j][c][2], d1 = Tyboxes[r][1][j][d][3],
              a2 = Tyboxes[r][2][j][a][0], b2 = Tyboxes[r][2][j][b][1], c2 = Tyboxes[r][2][j][c][2], d2 = Tyboxes[r][2][j][d][3],
              a3 = Tyboxes[r][3][j][a][0], b3 = Tyboxes[r][3][j][b][1], c3 = Tyboxes[r][3][j][c][2], d3 = Tyboxes[r][3][j][d][3];

      state[0][j] = (Xor[Xor[a0 >> 4][b0 >> 4]][Xor[c0 >> 4][d0 >> 4]] << 4) | Xor[Xor[a0 & 0xf][b0 & 0xf]][Xor[c0 & 0xf][d0 & 0xf]];
      state[1][j] = (Xor[Xor[a1 >> 4][b1 >> 4]][Xor[c1 >> 4][d1 >> 4]] << 4) | Xor[Xor[a1 & 0xf][b1 & 0xf]][Xor[c1 & 0xf][d1 & 0xf]];
      state[2][j] = (Xor[Xor[a2 >> 4][b2 >> 4]][Xor[c2 >> 4][d2 >> 4]] << 4) | Xor[Xor[a2 & 0xf][b2 & 0xf]][Xor[c2 & 0xf][d2 & 0xf]];
      state[3][j] = (Xor[Xor[a3 >> 4][b3 >> 4]][Xor[c3 >> 4][d3 >> 4]] << 4) | Xor[Xor[a3 & 0xf][b3 & 0xf]][Xor[c3 & 0xf][d3 & 0xf]];
    }
  }

  ShiftRows(state);

  // Using T-boxes:
  for (int x = 0; x < 4; x++) {
    for (int y = 0; y < 4; y++) {
      state[x][y] = Tboxes10[x][y][state[x][y]];
    }
  }

  // Copy the state to the output array.
  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
      out[i*4 + j] = state[j][i];
}

void aes128_oracle_decrypt(const uint8_t in[16],
    uint8_t out[16]) {
  uint8_t state[4][4];

  // Copy the input to the state.
  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
      state[j][i] = in[i*4 + j];

  // Using T-boxes:
  for (int x = 0; x < 4; x++) {
    for (int y = 0; y < 4; y++) {
      state[x][y] = InvTboxes[9][x][y][state[x][y]];
    }
  }

  InvShiftRows(state);
  for (int r = 9; r > 0; r--) {
    // Using InvTy(i) + T-boxes Tables (single step):
    for (int j = 0; j < 4; ++j) {
      uint8_t a = state[0][j], b = state[1][j],
              c = state[2][j], d = state[3][j];

      uint8_t a0 = InvTy[0][a][0], b0 = InvTy[0][b][1], c0 = InvTy[0][c][2], d0 = InvTy[0][d][3],
              a1 = InvTy[1][a][0], b1 = InvTy[1][b][1], c1 = InvTy[1][c][2], d1 = InvTy[1][d][3],
              a2 = InvTy[2][a][0], b2 = InvTy[2][b][1], c2 = InvTy[2][c][2], d2 = InvTy[2][d][3],
              a3 = InvTy[3][a][0], b3 = InvTy[3][b][1], c3 = InvTy[3][c][2], d3 = InvTy[3][d][3];

      uint8_t aa = (Xor[Xor[a0 >> 4][b0 >> 4]][Xor[c0 >> 4][d0 >> 4]] << 4) | Xor[Xor[a0 & 0xf][b0 & 0xf]][Xor[c0 & 0xf][d0 & 0xf]];
      uint8_t bb = (Xor[Xor[a1 >> 4][b1 >> 4]][Xor[c1 >> 4][d1 >> 4]] << 4) | Xor[Xor[a1 & 0xf][b1 & 0xf]][Xor[c1 & 0xf][d1 & 0xf]];
      uint8_t cc = (Xor[Xor[a2 >> 4][b2 >> 4]][Xor[c2 >> 4][d2 >> 4]] << 4) | Xor[Xor[a2 & 0xf][b2 & 0xf]][Xor[c2 & 0xf][d2 & 0xf]];
      uint8_t dd = (Xor[Xor[a3 >> 4][b3 >> 4]][Xor[c3 >> 4][d3 >> 4]] << 4) | Xor[Xor[a3 & 0xf][b3 & 0xf]][Xor[c3 & 0xf][d3 & 0xf]];

      state[0][j] = InvTboxes[r-1][0][j][aa];
      state[1][j] = InvTboxes[r-1][1][j][bb];
      state[2][j] = InvTboxes[r-1][2][j][cc];
      state[3][j] = InvTboxes[r-1][3][j][dd];
    }

    InvShiftRows(state);
  }

  // Copy the state to the output array.
  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
      out[i*4 + j] = state[j][i];
}
