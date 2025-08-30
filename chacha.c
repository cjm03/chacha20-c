#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <byteswap.h>
#include <math.h>
#include "chacha.h"

//-------------------------------------------------------------------------------------

void PRINTBLOCK(uint32_t *state)
{
    printf("0x%" PRIXPTR " 0x%" PRIXPTR " 0x%" PRIXPTR " 0x%" PRIXPTR "\n", (uintptr_t)state[0],  (uintptr_t)state[1], (uintptr_t)state[2], (uintptr_t)state[3]);
    printf("0x%" PRIXPTR " 0x%" PRIXPTR " 0x%" PRIXPTR " 0x%" PRIXPTR "\n", (uintptr_t)state[4],  (uintptr_t)state[5], (uintptr_t)state[6], (uintptr_t)state[7]);
    printf("0x%" PRIXPTR " 0x%" PRIXPTR " 0x%" PRIXPTR " 0x%" PRIXPTR "\n", (uintptr_t)state[8],  (uintptr_t)state[9], (uintptr_t)state[10], (uintptr_t)state[11]);
    printf("0x%" PRIXPTR " 0x%" PRIXPTR " 0x%" PRIXPTR " 0x%" PRIXPTR "\n\n", (uintptr_t)state[12], (uintptr_t)state[13], (uintptr_t)state[14], (uintptr_t)state[15]);
}

// apply the quarterround function on array passed as `out`
void QUARTERROUND(uint32_t* out, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
    out[a] += out[b];
    out[d] ^= out[a];
    out[d] = lrot32(out[d], 16);

    out[c] += out[d];
    out[b] ^= out[c];
    out[b] = lrot32(out[b], 12);

    out[a] += out[b];
    out[d] ^= out[a];
    out[d] = lrot32(out[d], 8);

    out[c] += out[d];
    out[b] ^= out[c];
    out[b] = lrot32(out[b], 7);
}

uint32_t lrot32(uint32_t n, unsigned int d) {
    return (n << d) | (n >> (INT_BITS - d));
}
uint32_t rrot32(uint32_t n, unsigned int d) {
    return lrot32(n, 32 - (d));
}
static uint32_t PACK4(const uint8_t* a) {
    uint32_t res = (uint32_t)a[0] << 0 * 8 
        | (uint32_t)a[1] << 1 * 8 
        | (uint32_t)a[2] << 2 * 8 
        | (uint32_t)a[3] << 3 * 8;
    return res;
}

void CHACHA20_INIT(Context* Context, const key256_t key, const nonce96_t nonce, uint32_t* count)
{
    Context->state[0]  = PACK4((const uint8_t*)CHACHA20_MAGICSTRING + 0 * 4);
    Context->state[1]  = PACK4((const uint8_t*)CHACHA20_MAGICSTRING + 1 * 4);
    Context->state[2]  = PACK4((const uint8_t*)CHACHA20_MAGICSTRING + 2 * 4);
    Context->state[3]  = PACK4((const uint8_t*)CHACHA20_MAGICSTRING + 3 * 4);
    Context->state[4]  = PACK4(key + 0 * 4);
    Context->state[5]  = PACK4(key + 1 * 4);
    Context->state[6]  = PACK4(key + 2 * 4);
    Context->state[7]  = PACK4(key + 3 * 4);
    Context->state[8]  = PACK4(key + 4 * 4);
    Context->state[9]  = PACK4(key + 5 * 4);
    Context->state[10] = PACK4(key + 6 * 4);
    Context->state[11] = PACK4(key + 7 * 4);
    Context->state[12] = *count;
    Context->state[13] = PACK4(nonce + 0 * 4);
    Context->state[14] = PACK4(nonce + 1 * 4);
    Context->state[15] = PACK4(nonce + 2 * 4);

    Context->index = 0;

    // PRINTBLOCK(Context->state);
}

void CHACHA20_BLOCK(const uint32_t in[16], uint32_t out[16])
{
    for (int i = 0; i < 16; i++) {
        out[i] = in[i];
    }

    for (int i = 0; i < 10; i++) {
        QUARTERROUND(out,  0,  4,  8, 12);      // 1
        QUARTERROUND(out,  1,  5,  9, 13);      // 2
        QUARTERROUND(out,  2,  6, 10, 14);      // 3
        QUARTERROUND(out,  3,  7, 11, 15);      // 4
        QUARTERROUND(out,  0,  5, 10, 15);      // 5
        QUARTERROUND(out,  1,  6, 11, 12);      // 6
        QUARTERROUND(out,  2,  7,  8, 13);      // 7
        QUARTERROUND(out,  3,  4,  9, 14);      // 8
    }

    for (int i = 0; i < 16; i++) {
        out[i] += in[i];
    }
}

// count: tells serialize how to store the transformed state in the keystream
//      1: [0]->[63]    2: [64]->[127] ...
// Applies to a block following the block operation
void CHACHA20_SERIALIZE(uint32_t* state, uint8_t* keystream, uint32_t count, unsigned long size)
{
    unsigned int offset = (count - 1) * 64;
    unsigned int bytes = (size > 64) ? 64 : size;
    for (unsigned int i = 0; i < bytes; i += 4) {
        uint32_t cur = state[i / 4];
        if (offset + i + 3 >= size) break;
        keystream[offset + i + 0] = cur & 0xff;                 
        keystream[offset + i + 1] = rrot32(cur, 8) & 0xff;     
        keystream[offset + i + 2] = rrot32(cur, 16) & 0xff;    
        keystream[offset + i + 3] = rrot32(cur, 24) & 0xff;     
    }
}

// print a certain amount the keystream
void PRINTSERIALIZED(const uint8_t* keystream, size_t size)
{
    size_t bytes = 0;
    printf("Serialized:\n%03zu | ", bytes);
    for (int i = 0; i < size; i++) {
        printf("%02x ", keystream[i]);
        if ((i + 1) % 16 == 0) {
            bytes += 16;
            printf("\n%03zu | ", bytes);
        }
    }
    printf("\n\n");
}

// Performs chacha20 on the rest of the plaintext if the initial keystream isnt enough
void CHACHA20_XOR(Context* Context, uint32_t* state, uint32_t* count, uint8_t* keystream, uint8_t* plaintext, unsigned long pt_size, uint8_t* ciphertext)
{
    int size_floored = floor((float)pt_size / 64);
    printf("\nSIZEFLOORED: %d\n", size_floored);
    for (int i = 0; i < size_floored; i++) {
        CHACHA20_BLOCK(Context->state, state);
        CHACHA20_SERIALIZE(state, keystream, *count, pt_size);
        Context->state[12]++;
    }
    for (int y = 0; y < pt_size; y++) {
        ciphertext[y] = plaintext[y] ^ keystream[y];
    }
}

void CHACHA20_ENCRYPT(Context* Context, const key256_t key, const nonce96_t nonce, uint8_t* plaintext, unsigned long pt_size)
{
    uint32_t count = 1;
    uint32_t* pCount = &count;

    uint32_t state[16];         // holds adapting state
    uint8_t* keystream = (uint8_t*)malloc(pt_size * sizeof(uint8_t) + 4);
    uint8_t* ciphertext = (uint8_t*)malloc(pt_size * sizeof(uint8_t) + 4);

    CHACHA20_INIT(Context, key, nonce, pCount);
    PRINTBLOCK(Context->state);
    CHACHA20_BLOCK(Context->state, state);   // Context.state = INITIAL BLOCK (to reference)
    PRINTBLOCK(state);
    CHACHA20_SERIALIZE(state, keystream, count, pt_size);
    // PRINTSERIALIZED(keystream, pt_size);
    count++;
    Context->state[12]++;
    CHACHA20_XOR(Context, state, pCount, keystream, plaintext, pt_size, ciphertext);
    PRINTSERIALIZED(keystream, pt_size);
    printf("FREEING\n");
    free(keystream);
    free(ciphertext);
}

void StrToHex(const char* in, uint8_t *out, size_t length)
{
    for (size_t i = 0; i < length; ++i) {
        out[i] = (uint8_t)in[i];
    }
}

// CURRENT TESTING IMPLEMENTATION. 
int main(void)
{
    const key256_t key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const nonce96_t nonce = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
    };
    const char* msg = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it. Ladies and Gentlemen of the class of '99: If I could jj5akjlsdf 11ua070735zsfasdf";
    unsigned long pt_len = strlen(msg);
    printf("%lu\n", pt_len);
    printf("%lu\n", pt_len * sizeof(uint8_t) + 4);
    printf("%hhu\n", (uint8_t)pt_len);
    uint8_t PT[pt_len];
    StrToHex(msg, PT, pt_len);
    Context Context;
    CHACHA20_ENCRYPT(&Context, key, nonce, PT, pt_len);

    // uint8_t PLAINTEXT[] = {
    //     0x4C, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x47, 0x65, 0x6E, 0x74, 0x6C,
    //     0x65, 0x6D, 0x65, 0x6E, 0x20, 0x6F, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6C, 0x61, 0x73,
    //     0x73, 0x20, 0x6F, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3A, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
    //     0x6F, 0x75, 0x6C, 0x64, 0x20, 0x6F, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6F, 0x75, 0x20, 0x6F,
    //     0x6E, 0x6C, 0x79, 0x20, 0x6F, 0x6E, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6F, 0x72, 0x20,
    //     0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2C, 0x20, 0x73, 0x75, 0x6E, 0x73,
    //     0x63, 0x72, 0x65, 0x65, 0x6E, 0x20, 0x77, 0x6F, 0x75, 0x6C, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
    //     0x74, 0x2E
    // };
    // const char* msg = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    // unsigned long pt_size = sizeof(PLAINTEXT);
    // Context Context;
    // CHACHA20_ENCRYPT(&Context, key, nonce, PLAINTEXT, pt_size);
    // printf("\n");
    // free(keystream);
    // free(ciphertext);
}

// void CHACHA20_SERIALIZE(uint32_t* state, uint8_t* keystream, uint32_t count, unsigned long size)
// {
//     int j = 0;
//     int x = 0;
//     int index = count * 16;
//     int start = index - 16;
//     int offset = (count - 1) * 64;
//     for (int i = start; i < index; i++) {
//         uint32_t cur = state[x];
//         keystream[0 + offset + j] = cur & 0xff;                 // This was my own  way to reorder the bytes
//         keystream[1 + offset + j] = rrot32(cur, 8) & 0xff;      // in little endian order which took me way too
//         keystream[2 + offset + j] = rrot32(cur, 16) & 0xff;     // to understand and implement. Something better
//         keystream[3 + offset + j] = rrot32(cur, 24) & 0xff;     // certainly exists but im proud of it
//         j += 4;
//         x++;
//         if (3 + offset + j > size) break;
//     }
// }
