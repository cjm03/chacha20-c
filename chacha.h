#ifndef CHACHA_H
#define CHACHA_H

#include <stdint.h>
#include <stddef.h>

#define INT_BITS 32
#define MAX_PLAINTEXT 1024
#define CHACHA20_MAGICSTRING "expand 32-byte k"

typedef uint8_t key256_t[32];
typedef uint8_t nonce96_t[12];

typedef struct {
    uint32_t state[16];
    uint8_t* keystream;
    uint32_t index;
    key256_t key;
    nonce96_t nonce;
} Context;

void PRINTBLOCK(uint32_t *state);
void QUARTERROUND(uint32_t* out, uint32_t a, uint32_t b, uint32_t c, uint32_t d);
uint32_t lrot32(uint32_t n, unsigned int d);
uint32_t rrot32(uint32_t n, unsigned int d);
static uint32_t PACK4(const uint8_t *a);
void CHACHA20_INIT(Context* Context, const key256_t key, const nonce96_t nonce, uint32_t* count);
void CHACHA20_BLOCK(const uint32_t in[16], uint32_t out[16]);
void CHACHA20_SERIALIZE(uint32_t* state, uint8_t* keystream, uint32_t count);
void PRINTSERIALIZED(const uint8_t* keystream, size_t size);
void CHACHA20_XOR(Context* Context, uint32_t* state, uint32_t* count, uint8_t* keystream,
                    uint8_t* plaintext, unsigned long pt_size, uint8_t* ciphertext);

#endif // CHACHA_H
