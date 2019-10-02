// Copyright 2019 AES WBC Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "aes.h"
#include "aes_private.h"

namespace {

// This implementation already considers the modification of steps as suggested
// by Muir's tutorial of 2013.
void Cipher(const uint8_t in[16], uint8_t out[16], const uint32_t roundKey[],
    int Nr) {
  uint8_t state[16] = {
    in[ 0], in[ 1], in[ 2], in[ 3],
    in[ 4], in[ 5], in[ 6], in[ 7],
    in[ 8], in[ 9], in[10], in[11],
    in[12], in[13], in[14], in[15],
  };

  // Perform the necessary number of rounds. The round key is added first.
  // The last round does not perform the MixColumns step.
  for (int r = 0; r < Nr-1; r++) {
    ShiftRows(state);
    AddRoundKeyAfterShift(state, &roundKey[r*4]);
    SubBytes(state);
    MixColumns(state);
  }
  ShiftRows(state);
  AddRoundKeyAfterShift(state, &roundKey[(Nr-1)*4]);
  SubBytes(state);
  AddRoundKey(state, &roundKey[Nr*4]);

  // Copy the state to the output array.
  for (int i = 0; i < 16; i++)
    out[i] = state[i];
}

}  // namespace

extern "C" {

void aes128_expand_keys(const uint8_t key[16],
    uint32_t w[44]) {
  ExpandKeys(key, w, 4, 10);
}

void aes128_encrypt(const uint8_t in[16], uint8_t out[16],
    const uint32_t roundKey[44]) {
  Cipher(in, out, roundKey, 10);
}

void aes192_expand_keys(const uint8_t key[16],
    uint32_t w[52]) {
  ExpandKeys(key, w, 6, 12);
}

void aes192_encrypt(const uint8_t in[16], uint8_t out[16],
    const uint32_t roundKey[52]) {
  Cipher(in, out, roundKey, 12);
}

void aes256_expand_keys(const uint8_t key[16],
    uint32_t w[60]) {
  ExpandKeys(key, w, 8, 14);
}

void aes256_encrypt(const uint8_t in[16], uint8_t out[16],
    const uint32_t roundKey[60]) {
  Cipher(in, out, roundKey, 14);
}

}  // extern "C"
