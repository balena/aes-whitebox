#ifndef AES128_ORACLE_H_
#define AES128_ORACLE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

void aes128_oracle_encrypt(const uint8_t in[16], uint8_t out[16]);

void aes128_oracle_encrypt_cfb(const uint8_t iv[16], const uint8_t* m,
    size_t len, uint8_t* c);
void aes128_oracle_decrypt_cfb(const uint8_t iv[16], const uint8_t* c,
    size_t len, uint8_t* m);

#ifdef __cplusplus
}
#endif

#endif  // AES128_ORACLE_H_
