#ifndef AES_H_
#define AES_H_

#include <stdint.h>

void aes_key_expand(const uint8_t key[16],
    uint32_t roundKey[44]);

void aes_encrypt(const uint8_t in[16], 
    uint8_t out[16],
    const uint32_t roundKey[44]);

void aes_decrypt(const uint8_t in[16],
    uint8_t out[16],
    const uint32_t roundKey[44]);

void aes_gen_xor_tables(uint8_t Xor[16][16]);

void aes_encrypt_gen_tables(uint8_t Tyboxes[9][4][4][256][4],
    uint8_t Tboxes10[4][4][256], const uint32_t roundKey[44]);

void aes_decrypt_gen_tables(uint8_t InvTboxes[10][4][4][256],
    uint8_t InvTy[4][256][4], const uint32_t roundKey[44]);

void aes_table_encrypt(const uint8_t in[16], 
    uint8_t out[16],
    uint8_t Tyboxes[9][4][4][256][4],
    uint8_t Tboxes10[4][4][256],
    const uint8_t Xor[16][16]);

void aes_table_decrypt(const uint8_t in[16],
    uint8_t out[16],
    const uint8_t InvTboxes[10][4][4][256],
    const uint8_t InvTy[4][256][4],
    const uint8_t Xor[16][16]);

#endif  /* AES_H_ */
