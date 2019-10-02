// Copyright 2019 AES WBC Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AES_WHITEBOX_H_
#define AES_WHITEBOX_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

void aes_whitebox_encrypt_cfb(const uint8_t iv[16], const uint8_t* m,
    size_t len, uint8_t* c);
void aes_whitebox_decrypt_cfb(const uint8_t iv[16], const uint8_t* c,
    size_t len, uint8_t* m);

void aes_whitebox_encrypt_ofb(const uint8_t iv[16], const uint8_t* m,
    size_t len, uint8_t* c);
void aes_whitebox_decrypt_ofb(const uint8_t iv[16], const uint8_t* c,
    size_t len, uint8_t* m);

void aes_whitebox_encrypt_ctr(const uint8_t nonce[16], const uint8_t* m,
    size_t len, uint8_t* c);
void aes_whitebox_decrypt_ctr(const uint8_t nonce[16], const uint8_t* c,
    size_t len, uint8_t* m);

#ifdef __cplusplus
}
#endif

#endif  // AES_WHITEBOX_H_
