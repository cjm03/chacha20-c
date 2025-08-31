#ifndef CHACHA_H
#define CHACHA_H
/*
 * TO USE, DEFINE:
 *      Context Context;
 *      const key256_t key = {0x91, 0x12, ...}
 *      const nonce96_t nonce = {0x00, 0x4a, ...}
 *      uint8_t plaintext[] = {0x72, 0x1a, ...}
 *      unsigned long plaintext_size = sizeof(plaintext)
 * THEN, CALL:
 *      CHACHA20_ENCRYPT(&Context, key, nonce, plaintext, plaintext_size)
*/

#include <stdint.h>
#include <stddef.h>

#define INT_BITS 32
#define MAX_PLAINTEXT 1024
#define CHACHA20_MAGICSTRING "expand 32-byte k"

typedef uint8_t key256_t[32];
typedef uint8_t nonce96_t[12];

typedef struct Context {
    uint32_t state[16];
    uint8_t* keystream;
    unsigned long index;
    uint8_t key[32];
    uint8_t nonce[12];
    uint32_t counter;
    uint8_t* buffer;
} Context;

void CHACHA20_CONTEXT_INIT(Context *Context, uint8_t key[], uint8_t nonce[], uint32_t counter, unsigned long ptlen);
void CHACHA20_INIT(Context* Context, uint8_t *key, uint8_t *nonce);
void CHACHA20_XOR(Context* Context, uint8_t* plaintext, unsigned long pt_size);
void CHACHA20_BLOCK(const uint32_t in[16], uint32_t out[16]);
void PRINTBLOCK(uint32_t *state);
void QUARTERROUND(uint32_t* out, uint32_t a, uint32_t b, uint32_t c, uint32_t d);
void CHACHA20_SERIALIZE(uint32_t* state, uint8_t* keystream, unsigned long index, unsigned long size);
void PRINTSERIALIZED(uint8_t* keystream, size_t size);
void StrToHex(const char* in, uint8_t *out, size_t length);
uint32_t lrot32(uint32_t n, unsigned int d);
uint32_t rrot32(uint32_t n, unsigned int d);
static uint32_t PACK4(const uint8_t *a);

#endif // CHACHA_H
