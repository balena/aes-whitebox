#include "aes128.h"

#include "aes128_internal.c"

void aes128_expand_keys(const uint8_t key[16],
    uint32_t w[44]) {
  ExpandKeys(key, w);
}

void aes128_encrypt(const uint8_t in[16],
    uint8_t out[16],
    const uint32_t roundKey[44]) {
  uint8_t state[4][4];

  // Copy input array (should be 16 bytes long) to a matrix (sequential bytes are ordered
  // by row, not col) called "state" for processing.
  // *** Implementation note: The official AES documentation references the state by
  // column, then row. Accessing an element in C requires row then column. Thus, all state
  // references in AES must have the column and row indexes reversed for C implementation.
  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
      state[j][i] = in[i*4 + j];

  // Perform the necessary number of rounds. The round key is added first.
  // The last round does not perform the MixColumns step.
  for (int r = 0; r < 9; r++) {
    ShiftRows(state);
    AddRoundKeyAfterShift(state, &roundKey[r*4]);
    SubBytes(state);
    MixColumns(state);
  }
  ShiftRows(state);
  AddRoundKeyAfterShift(state, &roundKey[36]);
  SubBytes(state);
  AddRoundKey(state, &roundKey[40]);

  // Copy the state to the output array.
  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
      out[i*4 + j] = state[j][i];
}

void aes128_decrypt(const uint8_t in[16],
    uint8_t out[16],
    const uint32_t roundKey[44]) {
  uint8_t state[4][4];

  // Copy the input to the state.
  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
      state[j][i] = in[i*4 + j];

  // Perform the necessary number of rounds. The round key is added first.
  // The last round does not perform the MixColumns step.
  AddRoundKey(state, &roundKey[40]);
  InvSubBytes(state);
  AddRoundKeyAfterShift(state, &roundKey[36]);
  InvShiftRows(state);
  for (int r = 9; r > 0; r--) {
    InvMixColumns(state);
    InvSubBytes(state);
    AddRoundKeyAfterShift(state, &roundKey[(r-1)*4]);
    InvShiftRows(state);
  }

  // Copy the state to the output array.
  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
      out[i*4 + j] = state[j][i];
}
