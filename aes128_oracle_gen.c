#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <sodium.h>
#include <flint/flint.h>
#include <flint/fmpz_mat.h>

#include "aes128_internal.c"

// Calculate the T-boxes, which is a combination of the AddRoundKeyAfterShift
// and the SubBytes functions.
static void CalculateTboxes(const uint32_t roundKey[44],
    uint8_t Tboxes[10][4][4][256]) {
  for (int x = 0; x < 256; x++) {
    for (int r = 0; r < 10; r++) {
      uint8_t state[4][4] = {
        { x, x, x, x },
        { x, x, x, x },
        { x, x, x, x },
        { x, x, x, x }
      };
      AddRoundKeyAfterShift(state, &roundKey[r*4]);
      SubBytes(state);
      if (r == 9) {
        AddRoundKey(state, &roundKey[40]);
      }
      for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
          Tboxes[r][i][j][x] = state[i][j];
        }
      }
    }
  }
}

static void CalculateInvTboxes(const uint32_t roundKey[16],
    uint8_t InvTboxes[10][4][4][256]) {
  for (int x = 0; x < 256; x++) {
    for (int r = 0; r < 10; r++) {
      uint8_t state[4][4] = {
        { x, x, x, x },
        { x, x, x, x },
        { x, x, x, x },
        { x, x, x, x }
      };
      if (r == 9) {
        AddRoundKey(state, &roundKey[40]);
      }
      InvSubBytes(state);
      AddRoundKeyAfterShift(state, &roundKey[r*4]);
      for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
          InvTboxes[r][i][j][x] = state[i][j];
        }
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

static void CalculateTyBoxes(const uint8_t Tboxes[10][4][4][256],
    const uint8_t Ty[4][256][4], uint8_t Tyboxes[9][4][4][256][4],
    uint8_t Tboxes10[4][4][256]) {
  for (int r = 0; r < 9; ++r)
    for (int i = 0; i < 4; ++i)
      for (int j = 0; j < 4; ++j)
        for (int x = 0; x < 256; x++)
          for (int k = 0; k < 4; k++)
            Tyboxes[r][i][j][x][k] = Ty[i][Tboxes[r][k][j][x]][k];

  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
      for (int x = 0; x < 256; x++)
        Tboxes10[i][j][x] = Tboxes[9][i][j][x];
}

static void CalculateInvTy(uint8_t InvTy[4][256][4]) {
  for (int x = 0; x < 256; x++) {
    InvTy[0][x][0] = gf_mul[x][5];
    InvTy[0][x][1] = gf_mul[x][3];
    InvTy[0][x][2] = gf_mul[x][4];
    InvTy[0][x][3] = gf_mul[x][2];

    InvTy[1][x][0] = gf_mul[x][2];
    InvTy[1][x][1] = gf_mul[x][5];
    InvTy[1][x][2] = gf_mul[x][3];
    InvTy[1][x][3] = gf_mul[x][4];

    InvTy[2][x][0] = gf_mul[x][4];
    InvTy[2][x][1] = gf_mul[x][2];
    InvTy[2][x][2] = gf_mul[x][5];
    InvTy[2][x][3] = gf_mul[x][3];

    InvTy[3][x][0] = gf_mul[x][3];
    InvTy[3][x][1] = gf_mul[x][4];
    InvTy[3][x][2] = gf_mul[x][2];
    InvTy[3][x][3] = gf_mul[x][5];
  }
}

static void ConstructInvertibleMatrix(fmpz_mat_t mat) {
  fmpz_t det;
  flint_rand_t state;

  flint_randinit(state);

  do {
    fmpz_mat_randbits(mat, state, 8);
    fmpz_mat_det(det, mat);
  } while(fmpz_get_ui(det) == 0);
  
  flint_randclear(state);
}

static void ConstructXorTables(uint8_t Xor[16][16]) {
  for (int i = 0; i < 16; i++)
    for (int j = 0; j < 16; j++)
      Xor[i][j] = i ^ j;
}

static void GenerateTables(const uint8_t key[16]) {
  uint32_t roundKey[44];

  uint8_t Tboxes[10][4][4][256];
  uint8_t Ty[4][256][4];

  uint8_t Tyboxes[9][4][4][256][4];
  uint8_t Tboxes10[4][4][256];

  uint8_t InvTboxes[10][4][4][256];
  uint8_t InvTy[4][256][4];

  uint8_t Xor[16][16];

  FILE* out = fopen("aes128_oracle_tables.c", "w");

  ExpandKeys(key, roundKey);

  CalculateTboxes(roundKey, Tboxes);
  CalculateTy(Ty);
  CalculateTyBoxes(Tboxes, Ty, Tyboxes, Tboxes10);

  CalculateInvTboxes(roundKey, InvTboxes);
  CalculateInvTy(InvTy);

  ConstructXorTables(Xor);

  fprintf(out, "static const uint8_t Tyboxes[9][4][4][256][4] = {\n");
  for (int r = 0; r < 9; r++) {
    fprintf(out, "  {\n");
    for (int i = 0; i < 4; i++) {
      fprintf(out, "    {\n");
      for (int j = 0; j < 4; j++) {
        fprintf(out, "      {\n");
        for (int x = 0; x < 256; x++) {
          if ((x % 4) == 0) {
            fprintf(out, "        { ");
          } else {
            fprintf(out, "{ ");
          }
          for (int k = 0; k < 4; k++) {
            fprintf(out, "0x%02x, ", Tyboxes[r][i][j][x][k]);
          }
          if (x > 0 && (x % 4) == 3) {
            fprintf(out, "},\n");
          } else {
            fprintf(out, "}, ");
          }
        }
        fprintf(out, "      },\n");
      }
      fprintf(out, "    },\n");
    }
    fprintf(out, "  },\n");
  }
  fprintf(out, "};\n\n");

  fprintf(out, "static const uint8_t Tboxes10[4][4][256] = {\n");
  for (int i = 0; i < 4; i++) {
    fprintf(out, "  {\n");
    for (int j = 0; j < 4; j++) {
      fprintf(out, "    {\n");
      for (int x = 0; x < 256; x++) {
        if (x % 16 == 0) {
          fprintf(out, "      ");
        }
        fprintf(out, "0x%02x, ", Tboxes10[i][j][x]);
        if (x % 16 == 15) {
          fprintf(out, "\n");
        }
      }
      fprintf(out, "    },\n");
    }
    fprintf(out, "  },\n");
  }
  fprintf(out, "};\n\n");

  fprintf(out, "static const uint8_t InvTboxes[10][4][4][256] = {\n");
  for (int r = 0; r < 10; r++) {
    fprintf(out, "  {\n");
    for (int i = 0; i < 4; i++) {
      fprintf(out, "    {\n");
      for (int j = 0; j < 4; j++) {
        fprintf(out, "      {\n");
        for (int x = 0; x < 256; x++) {
          if (x % 16 == 0) {
            fprintf(out, "        ");
          }
          fprintf(out, "0x%02x, ", InvTboxes[r][i][j][x]);
          if (x % 16 == 15) {
            fprintf(out, "\n");
          }
        }
        fprintf(out, "      },\n");
      }
      fprintf(out, "    },\n");
    }
    fprintf(out, "  },\n");
  }
  fprintf(out, "};\n\n");

  fprintf(out, "static const uint8_t InvTy[4][256][4] = {\n");
  for (int j = 0; j < 4; j++) {
    fprintf(out, "  {\n");
    for (int x = 0; x < 256; x++) {
      if ((x % 4) == 0) {
        fprintf(out, "    { ");
      } else {
        fprintf(out, "{ ");
      }
      for (int k = 0; k < 4; k++) {
        fprintf(out, "0x%02x, ", InvTy[j][x][k]);
      }
      if (x > 0 && (x % 4) == 3) {
        fprintf(out, "},\n");
      } else {
        fprintf(out, "}, ");
      }
    }
    fprintf(out, "  },\n");
  }
  fprintf(out, "};\n\n");

  fprintf(out, "static const uint8_t Xor[16][16] = {\n");
  for (int i = 0; i < 16; i++) {
    fprintf(out, "  { ");
    for (int j = 0; j < 16; j++) {
      fprintf(out, "0x%02x, ", Xor[i][j]);
    }
    fprintf(out, "},\n");
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
