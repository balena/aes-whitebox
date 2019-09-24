#ifndef AES128_ORACLE_H_
#define AES128_ORACLE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void aes128_oracle_encrypt(const uint8_t in[16], uint8_t out[16]);
void aes128_oracle_decrypt(const uint8_t in[16], uint8_t out[16]);

#ifdef __cplusplus
}
#endif

#endif  // AES128_ORACLE_H_
