// Copyright 2019 AES-128 WBC Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AES128_ORACLE_H_
#define AES128_ORACLE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

void aes128_oracle_encrypt_cfb(const uint8_t iv[16], const uint8_t* m,
    size_t len, uint8_t* c);
void aes128_oracle_decrypt_cfb(const uint8_t iv[16], const uint8_t* c,
    size_t len, uint8_t* m);

#ifdef __cplusplus
}
#endif

#endif  // AES128_ORACLE_H_
