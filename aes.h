// Copyright 2019 AES WBC Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AES_H_
#define AES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void aes128_expand_keys(const uint8_t key[16],
    uint32_t roundKey[44]);

void aes128_encrypt(const uint8_t in[16], 
    uint8_t out[16],
    const uint32_t roundKey[44]);

void aes192_expand_keys(const uint8_t key[24],
    uint32_t roundKey[52]);

void aes192_encrypt(const uint8_t in[16], 
    uint8_t out[16],
    const uint32_t roundKey[52]);

void aes256_expand_keys(const uint8_t key[32],
    uint32_t roundKey[60]);

void aes256_encrypt(const uint8_t in[16], 
    uint8_t out[16],
    const uint32_t roundKey[60]);

#ifdef __cplusplus
}
#endif

#endif  /* AES_H_ */
