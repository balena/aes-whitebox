#include <stdio.h>

#include "aes128.h"
#include "aes128_private.h"

extern "C" {

void aes128_expand_keys(const uint8_t key[16],
    uint32_t w[44]) {
  ExpandKeys(key, w);
}

// This implementation already considers the modification of steps as suggested
// by Muir's tutorial of 2013.
void aes128_encrypt(const uint8_t in[16],
    uint8_t out[16],
    const uint32_t roundKey[44]) {
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
    AddRoundKeyAfterShift(state, &roundKey[r*4]);
    SubBytes(state);
    MixColumns(state);
  }
  ShiftRows(state);
  AddRoundKeyAfterShift(state, &roundKey[36]);
  SubBytes(state);
  AddRoundKey(state, &roundKey[40]);

  // Copy the state to the output array.
  for (int i = 0; i < 16; i++)
    out[i] = state[i];
}

}  // extern "C"
