#ifndef MD5_H
#define MD5_H

#include <stddef.h>

typedef unsigned int uint32;
typedef unsigned char uint8;

typedef struct {
    uint32 h[4];
    uint8 buffer[64];
    uint32 bits[2];
} MD5_CTX;

void md5_init(MD5_CTX *ctx);
void md5_update(MD5_CTX *ctx, const uint8 *input, size_t len);
void md5_final(uint8 digest[16], MD5_CTX *ctx);
void md5_digest(const char *str, size_t len, uint8 digest[16]);

#endif
