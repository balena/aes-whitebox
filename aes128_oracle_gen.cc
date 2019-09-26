#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#include <iostream>
#include <fstream>

#include <NTL/mat_GF2.h>

#include "aes128_internal.c"

template<typename T>
inline NTL::vec_GF2 from_scalar(T in);

template<>
inline NTL::vec_GF2 from_scalar(uint8_t in) {
  NTL::vec_GF2 result;
  result.SetLength(8);
  for (int i = 0; i < 8; i++) {
    result[7 - i] = ((in >> i) & 1);
  }
  return result;
}

template<>
inline NTL::vec_GF2 from_scalar(uint32_t in) {
  NTL::vec_GF2 result;
  result.SetLength(32);
  for (int i = 0; i < 32; i++) {
    result[31 - i] = ((in >> i) & 1);
  }
  return result;
}

template<typename T>
inline T to_scalar(const NTL::vec_GF2& in);

template<>
inline uint8_t to_scalar(const NTL::vec_GF2& in) {
  uint8_t result = 0;
  for (int i = 0; i < 2; i++) {
    long i0 = NTL::rep(in[i*4+0]), i1 = NTL::rep(in[i*4+1]),
         i2 = NTL::rep(in[i*4+2]), i3 = NTL::rep(in[i*4+3]);
    result = (result << 4) | (i0 << 3) | (i1 << 2) | (i2 << 1) | (i3 << 0);
  }
  return result;
}

template<>
inline uint32_t to_scalar(const NTL::vec_GF2& in) {
  uint32_t result = 0;
  for (int i = 0; i < 8; i++) {
    long i0 = NTL::rep(in[i*4+0]), i1 = NTL::rep(in[i*4+1]),
         i2 = NTL::rep(in[i*4+2]), i3 = NTL::rep(in[i*4+3]);
    result = (result << 4) | (i0 << 3) | (i1 << 2) | (i2 << 1) | (i3 << 0);
  }
  return result;
}

template<typename T>
inline T mul(const NTL::mat_GF2& mat, T x) {
  return to_scalar<T>(mat * from_scalar<T>(x));
}

static NTL::mat_GF2 GenerateGF2RandomMatrix(int dimension) {
  NTL::mat_GF2 mat(NTL::INIT_SIZE, dimension, dimension);
  for (int i = 0; i < dimension; i++) {
    for (int j = 0; j < dimension; j++) {
      mat[i][j] = NTL::random_GF2();
    }
  }
  return mat;
}

static NTL::mat_GF2 GenerateRandomGF2InvertibleMatrix(int dimension) {
  for (;;) {
    NTL::mat_GF2 result = GenerateGF2RandomMatrix(dimension);
    if (NTL::determinant(result) != 0)
      return result;
  }
}

static void Generate8x8MixingBijections(NTL::mat_GF2 L[9][16]) {
  for (int r = 0; r < 9; r++) {
    for (int i = 0; i < 16; i++) {
      L[r][i] = GenerateRandomGF2InvertibleMatrix(8);
    }
  }
}

static void Generate32x32MixingBijections(NTL::mat_GF2 MB[9][4]) {
  for (int r = 0; r < 9; r++) {
    for (int i = 0; i < 4; i++) {
      MB[r][i] = GenerateRandomGF2InvertibleMatrix(32);
    }
  }
}

// Calculate the T-boxes, which is a combination of the AddRoundKeyAfterShift
// and the SubBytes functions.
static void CalculateTboxes(const uint32_t roundKey[44],
    uint8_t Tboxes[10][16][256]) {
  for (int r = 0; r < 10; r++) {
    for (int x = 0; x < 256; x++) {
      uint8_t state[16] = {
        (uint8_t)x, (uint8_t)x, (uint8_t)x, (uint8_t)x,
        (uint8_t)x, (uint8_t)x, (uint8_t)x, (uint8_t)x,
        (uint8_t)x, (uint8_t)x, (uint8_t)x, (uint8_t)x,
        (uint8_t)x, (uint8_t)x, (uint8_t)x, (uint8_t)x
      };
      AddRoundKeyAfterShift(state, &roundKey[r*4]);
      SubBytes(state);
      if (r == 9) {
        AddRoundKey(state, &roundKey[40]);
      }
      for (int i = 0; i < 16; i++) {
        Tboxes[r][i][x] = state[i];
      }
    }
  }
}

static void CalculateTy(uint8_t Ty[4][256][4]) {
  for (int x = 0; x < 256; x++) {
    Ty[0][x][0] = gf_mul[x][0];
    Ty[0][x][1] = gf_mul[x][1];
    Ty[0][x][2] = x;
    Ty[0][x][3] = x;

    Ty[1][x][0] = x;
    Ty[1][x][1] = gf_mul[x][0];
    Ty[1][x][2] = gf_mul[x][1];
    Ty[1][x][3] = x;

    Ty[2][x][0] = x;
    Ty[2][x][1] = x;
    Ty[2][x][2] = gf_mul[x][0];
    Ty[2][x][3] = gf_mul[x][1];

    Ty[3][x][0] = gf_mul[x][1];
    Ty[3][x][1] = x;
    Ty[3][x][2] = x;
    Ty[3][x][3] = gf_mul[x][0];
  }
}

static void CalculateInvTy(uint32_t InvTy[4][256]) {
  for (int x = 0; x < 256; x++) {
    InvTy[0][x] = gf_mul[x][5] << 24
                | gf_mul[x][3] << 16
                | gf_mul[x][4] <<  8
                | gf_mul[x][2] <<  0;

    InvTy[1][x] = gf_mul[x][2] << 24
                | gf_mul[x][5] << 16
                | gf_mul[x][3] <<  8
                | gf_mul[x][4] <<  0;

    InvTy[2][x] = gf_mul[x][4] << 24
                | gf_mul[x][2] << 16
                | gf_mul[x][5] <<  8
                | gf_mul[x][3] <<  0;

    InvTy[3][x] = gf_mul[x][3] << 24
                | gf_mul[x][4] << 16
                | gf_mul[x][2] <<  8
                | gf_mul[x][5] <<  0;
  }
}

static void CalculateInvTboxes(const uint32_t roundKey[16],
    const NTL::mat_GF2 L[9][16], const NTL::mat_GF2 MB[9][4],
    uint8_t InvTboxes[10][16][256], uint32_t InvTy[4][256],
    uint32_t MBL[9][16][256]) {
  CalculateInvTy(InvTy);

  for (int x = 0; x < 256; x++) {
    for (int r = 0; r < 10; r++) {
      uint8_t state[16] = {
        (uint8_t)x, (uint8_t)x, (uint8_t)x, (uint8_t)x,
        (uint8_t)x, (uint8_t)x, (uint8_t)x, (uint8_t)x,
        (uint8_t)x, (uint8_t)x, (uint8_t)x, (uint8_t)x,
        (uint8_t)x, (uint8_t)x, (uint8_t)x, (uint8_t)x
      };
      if (r == 9) {
        AddRoundKey(state, &roundKey[40]);
      }
      InvSubBytes(state);
      AddRoundKeyAfterShift(state, &roundKey[r*4]);
      for (int i = 0; i < 16; i++) {
        InvTboxes[r][i][x] = state[i];
      }
    }
  }
}

static void print_state(uint8_t state[16]) {
  printf("[");
  for (int i = 0; i < 4; i++) {
    printf("[%d, %d, %d, %d]\n",
        state[i*4 + 0], state[i*4 + 1],
        state[i*4 + 2], state[i*4 + 3]);
  }
  printf("]\n");
}

static void CalculateTyBoxes(const uint8_t Tboxes[10][16][256],
    const uint8_t Ty[4][256][4], const NTL::mat_GF2 L[9][16],
    const NTL::mat_GF2 MB[9][4], uint32_t Tyboxes[9][16][256],
    uint8_t Tboxes10[16][256], uint32_t MBL[9][16][256]) {
#if 0
  {
    uint8_t state[4][4] = {
      {  0,  1,  2,  3, },
      {  4,  5,  6,  7, },
      {  8,  9, 10, 11, },
      { 12, 13, 14, 15, },
    };

    for (int r = 0; r < 9; r++) {
      printf("-- Round %d:\n", r);
      print_state(state);

      ShiftRowsR(state);

      if (r > 0) {
        for (int i = 0; i < 4; i++)
          for (int j = 0; j < 4; j++)
            state[i][j] = mul<uint8_t>(NTL::inv(L[r-1][i][j]), state[i][j]);

        printf(">> After decoding with inv(L[%d][i][j]):\n", r);
        print_state(state);
      }

      for (int j = 0; j < 4; j++) {
        uint32_t out0 = mul<uint32_t>(MB[r][j], state[j][0] << 24);
        uint32_t out1 = mul<uint32_t>(MB[r][j], state[j][1] << 16);
        uint32_t out2 = mul<uint32_t>(MB[r][j], state[j][2] <<  8);
        uint32_t out3 = mul<uint32_t>(MB[r][j], state[j][3] <<  0);

        uint32_t result = out0 ^ out1 ^ out2 ^ out3;
        state[j][0] = result >> 24;
        state[j][1] = result >> 16;
        state[j][2] = result >>  8;
        state[j][3] = result >>  0;
      }

      for (int j = 0; j < 4; j++) {
        uint32_t out0 = mul<uint32_t>(NTL::inv(MB[r][j]), state[j][0] << 24);
        uint32_t out1 = mul<uint32_t>(NTL::inv(MB[r][j]), state[j][1] << 16);
        uint32_t out2 = mul<uint32_t>(NTL::inv(MB[r][j]), state[j][2] <<  8);
        uint32_t out3 = mul<uint32_t>(NTL::inv(MB[r][j]), state[j][3] <<  0);

        uint32_t result = out0 ^ out1 ^ out2 ^ out3;
        state[j][0] = result >> 24;
        state[j][1] = result >> 16;
        state[j][2] = result >>  8;
        state[j][3] = result >>  0;
      }

      for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
          state[i][j] =
            mul<uint8_t>(L[r][preshift[i][j] >> 2][preshift[i][j] & 0x3], state[i][j]);
        }
      }

      printf(">> After encoding with L[%d][i][j]:\n", r);
      print_state(state);
    }

    printf("-- Round %d:\n", 9);
    print_state(state);

    ShiftRowsR(state);

    for (int i = 0; i < 4; i++)
      for (int j = 0; j < 4; j++)
        state[i][j] = mul<uint8_t>(NTL::inv(L[8][i][j]), state[i][j]);

    printf(">> After decoding with inv(L[%d][i][j]):\n", 0);
    print_state(state);
  }
#endif

#define ENABLE_L 1
#define ENABLE_MB 1

  for (int r = 0; r < 9; r++) {
    for (int x = 0; x < 256; x++) {
      for (int j = 0; j < 4; j++) {
#if !ENABLE_L
        uint8_t in0 = x, in1 = x, in2 = x, in3 = x;
#else
        // -- Precompute MB × Ty × Tbox × inv(L), except for first round
        //uint8_t in0 = (r < 1) ? x : mul<uint8_t>(NTL::inv(L[r-1][j][0]), x);
        //uint8_t in1 = (r < 1) ? x : mul<uint8_t>(NTL::inv(L[r-1][j][1]), x);
        //uint8_t in2 = (r < 1) ? x : mul<uint8_t>(NTL::inv(L[r-1][j][2]), x);
        //uint8_t in3 = (r < 1) ? x : mul<uint8_t>(NTL::inv(L[r-1][j][3]), x);
        uint8_t in0 = (r < 1) ? x : mul<uint8_t>(NTL::inv(L[r-1][0]), x);
        uint8_t in1 = (r < 1) ? x : mul<uint8_t>(NTL::inv(L[r-1][0]), x);
        uint8_t in2 = (r < 1) ? x : mul<uint8_t>(NTL::inv(L[r-1][0]), x);
        uint8_t in3 = (r < 1) ? x : mul<uint8_t>(NTL::inv(L[r-1][0]), x);
#endif

        uint8_t a0 = Ty[0][Tboxes[r][j*4 + 0][in0]][0],
                b0 = Ty[0][Tboxes[r][j*4 + 1][in0]][1],
                c0 = Ty[0][Tboxes[r][j*4 + 2][in0]][2],
                d0 = Ty[0][Tboxes[r][j*4 + 3][in0]][3];

        uint8_t a1 = Ty[1][Tboxes[r][j*4 + 0][in1]][0],
                b1 = Ty[1][Tboxes[r][j*4 + 1][in1]][1],
                c1 = Ty[1][Tboxes[r][j*4 + 2][in1]][2],
                d1 = Ty[1][Tboxes[r][j*4 + 3][in1]][3];

        uint8_t a2 = Ty[2][Tboxes[r][j*4 + 0][in2]][0],
                b2 = Ty[2][Tboxes[r][j*4 + 1][in2]][1],
                c2 = Ty[2][Tboxes[r][j*4 + 2][in2]][2],
                d2 = Ty[2][Tboxes[r][j*4 + 3][in2]][3];

        uint8_t a3 = Ty[3][Tboxes[r][j*4 + 0][in3]][0],
                b3 = Ty[3][Tboxes[r][j*4 + 1][in3]][1],
                c3 = Ty[3][Tboxes[r][j*4 + 2][in3]][2],
                d3 = Ty[3][Tboxes[r][j*4 + 3][in3]][3];

#if !ENABLE_MB
        uint32_t out0 = (a0 << 24) | (a1 << 16) | (a2 << 8) | a3;
        uint32_t out1 = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
        uint32_t out2 = (c0 << 24) | (c1 << 16) | (c2 << 8) | c3;
        uint32_t out3 = (d0 << 24) | (d1 << 16) | (d2 << 8) | d3;
#else
        uint32_t out0 = mul<uint32_t>(MB[r][j], (a0 << 24) | (a1 << 16) | (a2 << 8) | a3);
        uint32_t out1 = mul<uint32_t>(MB[r][j], (b0 << 24) | (b1 << 16) | (b2 << 8) | b3);
        uint32_t out2 = mul<uint32_t>(MB[r][j], (c0 << 24) | (c1 << 16) | (c2 << 8) | c3);
        uint32_t out3 = mul<uint32_t>(MB[r][j], (d0 << 24) | (d1 << 16) | (d2 << 8) | d3);
#endif

        Tyboxes[r][j*4 + 0][x] = out0;
        Tyboxes[r][j*4 + 1][x] = out1;
        Tyboxes[r][j*4 + 2][x] = out2;
        Tyboxes[r][j*4 + 3][x] = out3;

#if !ENABLE_MB
        uint32_t lmb0 = x << 24;
        uint32_t lmb1 = x << 16;
        uint32_t lmb2 = x <<  8;
        uint32_t lmb3 = x <<  0;
#else
        uint32_t lmb0 = mul<uint32_t>(NTL::inv(MB[r][j]), x << 24);
        uint32_t lmb1 = mul<uint32_t>(NTL::inv(MB[r][j]), x << 16);
        uint32_t lmb2 = mul<uint32_t>(NTL::inv(MB[r][j]), x <<  8);
        uint32_t lmb3 = mul<uint32_t>(NTL::inv(MB[r][j]), x <<  0);
#endif

#if !ENABLE_L
        MBL[r][j*4 + 0][x] = lmb0;
        MBL[r][j*4 + 1][x] = lmb1;
        MBL[r][j*4 + 2][x] = lmb2;
        MBL[r][j*4 + 3][x] = lmb3;
#else
        // -- Precompute L × inv(MB) [ z1, z2, z3, z4 ], considering the input of the next round
        //MBL[r][j][0][x] = (mul<uint8_t>(L[r][preshift[j][0] >> 2][preshift[j][0] & 0x3], lmb0 >> 24) << 24)
        //                | (mul<uint8_t>(L[r][preshift[j][1] >> 2][preshift[j][1] & 0x3], lmb0 >> 16) << 16)
        //                | (mul<uint8_t>(L[r][preshift[j][2] >> 2][preshift[j][2] & 0x3], lmb0 >>  8) <<  8)
        //                | (mul<uint8_t>(L[r][preshift[j][3] >> 2][preshift[j][3] & 0x3], lmb0 >>  0) <<  0);
       
        //MBL[r][j][1][x] = (mul<uint8_t>(L[r][preshift[j][0] >> 2][preshift[j][0] & 0x3], lmb1 >> 24) << 24)
        //                | (mul<uint8_t>(L[r][preshift[j][1] >> 2][preshift[j][1] & 0x3], lmb1 >> 16) << 16)
        //                | (mul<uint8_t>(L[r][preshift[j][2] >> 2][preshift[j][2] & 0x3], lmb1 >>  8) <<  8)
        //                | (mul<uint8_t>(L[r][preshift[j][3] >> 2][preshift[j][3] & 0x3], lmb1 >>  0) <<  0);
       
        //MBL[r][j][2][x] = (mul<uint8_t>(L[r][preshift[j][0] >> 2][preshift[j][0] & 0x3], lmb2 >> 24) << 24)
        //                | (mul<uint8_t>(L[r][preshift[j][1] >> 2][preshift[j][1] & 0x3], lmb2 >> 16) << 16)
        //                | (mul<uint8_t>(L[r][preshift[j][2] >> 2][preshift[j][2] & 0x3], lmb2 >>  8) <<  8)
        //                | (mul<uint8_t>(L[r][preshift[j][3] >> 2][preshift[j][3] & 0x3], lmb2 >>  0) <<  0);
       
        //MBL[r][j][3][x] = (mul<uint8_t>(L[r][preshift[j][0] >> 2][preshift[j][0] & 0x3], lmb3 >> 24) << 24)
        //                | (mul<uint8_t>(L[r][preshift[j][1] >> 2][preshift[j][1] & 0x3], lmb3 >> 16) << 16)
        //                | (mul<uint8_t>(L[r][preshift[j][2] >> 2][preshift[j][2] & 0x3], lmb3 >>  8) <<  8)
        //                | (mul<uint8_t>(L[r][preshift[j][3] >> 2][preshift[j][3] & 0x3], lmb3 >>  0) <<  0);

        MBL[r][j*4 + 0][x] = (mul<uint8_t>(L[r][InvShiftRowsTab[0]], lmb0 >> 24) << 24)
                           | (mul<uint8_t>(L[r][InvShiftRowsTab[0]], lmb0 >> 16) << 16)
                           | (mul<uint8_t>(L[r][InvShiftRowsTab[0]], lmb0 >>  8) <<  8)
                           | (mul<uint8_t>(L[r][InvShiftRowsTab[0]], lmb0 >>  0) <<  0);

        MBL[r][j*4 + 1][x] = (mul<uint8_t>(L[r][InvShiftRowsTab[0]], lmb1 >> 24) << 24)
                           | (mul<uint8_t>(L[r][InvShiftRowsTab[0]], lmb1 >> 16) << 16)
                           | (mul<uint8_t>(L[r][InvShiftRowsTab[0]], lmb1 >>  8) <<  8)
                           | (mul<uint8_t>(L[r][InvShiftRowsTab[0]], lmb1 >>  0) <<  0);

        MBL[r][j*4 + 2][x] = (mul<uint8_t>(L[r][InvShiftRowsTab[0]], lmb2 >> 24) << 24)
                           | (mul<uint8_t>(L[r][InvShiftRowsTab[0]], lmb2 >> 16) << 16)
                           | (mul<uint8_t>(L[r][InvShiftRowsTab[0]], lmb2 >>  8) <<  8)
                           | (mul<uint8_t>(L[r][InvShiftRowsTab[0]], lmb2 >>  0) <<  0);

        MBL[r][j*4 + 3][x] = (mul<uint8_t>(L[r][InvShiftRowsTab[0]], lmb3 >> 24) << 24)
                           | (mul<uint8_t>(L[r][InvShiftRowsTab[0]], lmb3 >> 16) << 16)
                           | (mul<uint8_t>(L[r][InvShiftRowsTab[0]], lmb3 >>  8) <<  8)
                           | (mul<uint8_t>(L[r][InvShiftRowsTab[0]], lmb3 >>  0) <<  0);
#endif
      }
    }
  }

  for (int x = 0; x < 256; x++) {
    for (int j = 0; j < 4; j++) {
#if !ENABLE_L
      uint8_t in0 = x, in1 = x, in2 = x, in3 = x;
#else
      // -- Precompute Tbox × inv(L)
      //uint8_t in = mul<uint8_t>(NTL::inv(L[8][i][j]), x);
      uint8_t in0 = mul<uint8_t>(NTL::inv(L[8][0]), x);
      uint8_t in1 = mul<uint8_t>(NTL::inv(L[8][0]), x);
      uint8_t in2 = mul<uint8_t>(NTL::inv(L[8][0]), x);
      uint8_t in3 = mul<uint8_t>(NTL::inv(L[8][0]), x);
#endif
      Tboxes10[j*4 + 0][x] = Tboxes[9][j*4 + 0][in0];
      Tboxes10[j*4 + 1][x] = Tboxes[9][j*4 + 1][in1];
      Tboxes10[j*4 + 2][x] = Tboxes[9][j*4 + 2][in2];
      Tboxes10[j*4 + 3][x] = Tboxes[9][j*4 + 3][in3];
    }
  }
}

static void ConstructXorTables(uint8_t Xor[16][16]) {
  for (int i = 0; i < 16; i++)
    for (int j = 0; j < 16; j++)
      Xor[i][j] = i ^ j;
}

static void GenerateTables(const uint8_t key[16]) {
  uint32_t roundKey[44];

  uint8_t Tboxes[10][16][256];
  uint8_t Ty[4][256][4];

  uint32_t Tyboxes[9][16][256];
  uint8_t Tboxes10[16][256];

  uint8_t InvTboxes[10][16][256];
  uint32_t InvTy[4][256];

  NTL::mat_GF2 L[9][16], MB[9][4];

  uint32_t MBL[9][16][256], InvMBL[9][16][256];

  FILE* out = fopen("aes128_oracle_tables.c", "w");

  ExpandKeys(key, roundKey);

  CalculateTboxes(roundKey, Tboxes);
  CalculateTy(Ty);

  Generate8x8MixingBijections(L);
  Generate32x32MixingBijections(MB);

  CalculateTyBoxes(Tboxes, Ty, L, MB, Tyboxes, Tboxes10, MBL);
  CalculateInvTboxes(roundKey, L, MB, InvTboxes, InvTy, InvMBL);

  fprintf(out, "static const uint32_t Tyboxes[9][16][256] = {\n");
  for (int r = 0; r < 9; r++) {
    fprintf(out, "  {\n");
    for (int i = 0; i < 16; i++) {
      fprintf(out, "    {\n");
      for (int x = 0; x < 256; x++) {
        if ((x % 8) == 0) {
          fprintf(out, "      ");
        }
        fprintf(out, "0x%08x,", Tyboxes[r][i][x]);
        if (x > 0 && (x % 8) == 7) {
          fprintf(out, "\n");
        } else {
          fprintf(out, " ");
        }
      }
      fprintf(out, "    },\n");
    }
    fprintf(out, "  },\n");
  }
  fprintf(out, "};\n\n");

  fprintf(out, "static const uint8_t Tboxes10[16][256] = {\n");
  for (int i = 0; i < 16; i++) {
    fprintf(out, "  {\n");
    for (int x = 0; x < 256; x++) {
      if (x % 16 == 0) {
        fprintf(out, "    ");
      }
      fprintf(out, "0x%02x, ", Tboxes10[i][x]);
      if (x % 16 == 15) {
        fprintf(out, "\n");
      }
    }
    fprintf(out, "  },\n");
  }
  fprintf(out, "};\n\n");

  fprintf(out, "static const uint8_t InvTboxes[10][16][256] = {\n");
  for (int r = 0; r < 10; r++) {
    fprintf(out, "  {\n");
    for (int i = 0; i < 16; i++) {
      fprintf(out, "    {\n");
      for (int x = 0; x < 256; x++) {
        if (x % 16 == 0) {
          fprintf(out, "      ");
        }
        fprintf(out, "0x%02x, ", InvTboxes[r][i][x]);
        if (x % 16 == 15) {
          fprintf(out, "\n");
        }
      }
      fprintf(out, "    },\n");
    }
    fprintf(out, "  },\n");
  }
  fprintf(out, "};\n\n");

  fprintf(out, "static const uint32_t InvTy[4][256] = {\n");
  for (int j = 0; j < 4; j++) {
    fprintf(out, "  {\n");
    for (int x = 0; x < 256; x++) {
      if ((x % 8) == 0) {
        fprintf(out, "    ");
      }
      fprintf(out, "0x%08x,", InvTy[j][x]);
      if (x > 0 && (x % 8) == 7) {
        fprintf(out, "\n");
      } else {
        fprintf(out, " ");
      }
    }
    fprintf(out, "  },\n");
  }
  fprintf(out, "};\n\n");

  fprintf(out, "static const uint32_t MBL[9][16][256] = {\n");
  for (int r = 0; r < 9; r++) {
    fprintf(out, "  {\n");
    for (int i = 0; i < 16; i++) {
      fprintf(out, "    {\n");
      for (int x = 0; x < 256; x++) {
        if ((x % 8) == 0) {
          fprintf(out, "      ");
        }
        fprintf(out, "0x%08x,", MBL[r][i][x]);
        if (x > 0 && (x % 8) == 7) {
          fprintf(out, "\n");
        } else {
          fprintf(out, " ");
        }
      }
      fprintf(out, "    },\n");
    }
    fprintf(out, "  },\n");
  }
  fprintf(out, "};\n\n");

  fflush(out);
  fclose(out);
}

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

static void read_key(const char *in, uint8_t key[16]) {
  if (strlen(in) != 32)
    err_quit("Invalid key (should be a valid 128-bits hexadecimal string)");
  for (int i = 0; i < 16; i++) {
    sscanf(in + i * 2, "%2hhx", key + i);
  }
}

int main(int argc, char* argv[]) {
  uint8_t key[16];

  if (argc != 2)
    err_quit("Syntax: aes128_oracle_gen <AES-128-hex-key>");

  read_key(argv[1], key);
  GenerateTables(key);
  return 0;
}
