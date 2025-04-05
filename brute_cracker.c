#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>

#define CHARSET "abcdefghijklmnopqrstuvwxyz"
#define CHARSET_SIZE 26
#define MAX_LEN 12

typedef unsigned int uint32;
typedef unsigned char uint8;

volatile int keep_running = 1;
unsigned long long attempts = 0;

// MD5 STRUCT
typedef struct {
    uint32 h[4];
    uint8 buffer[64];
    uint32 bits[2];
} MD5_CTX;

void md5_transform(uint32 h[4], const uint8 block[64]);
void md5_update(MD5_CTX *ctx, const uint8 *input, size_t len);
void md5_init(MD5_CTX *ctx);
void md5_final(uint8 digest[16], MD5_CTX *ctx);
void md5_string_len(const char *str, size_t len, char output[33]);

void md5_string_len(const char *str, size_t len, char output[33]) {
    MD5_CTX ctx;
    uint8 digest[16];
    md5_init(&ctx);
    md5_update(&ctx, (const uint8*)str, len);
    md5_final(digest, &ctx);
    for (int i = 0; i < 16; ++i) {
        static const char hex[] = "0123456789abcdef";
        output[i*2] = hex[digest[i] >> 4];
        output[i*2+1] = hex[digest[i] & 0x0F];
    }
    output[32] = '\0';
}

int brute_force(char* buffer, int position, int max_len, const char* target_hash, time_t start_time) {
    static char hash[33];

    if (!keep_running) return 0;

    for (int i = 0; i < CHARSET_SIZE; i++) {
        if (!keep_running) return 0;

        buffer[position] = CHARSET[i];

        if (position + 1 < max_len) {
            brute_force(buffer, position + 1, max_len, target_hash, start_time);
        }

        buffer[position + 1] = '\0';
        size_t guess_len = position + 1;
        md5_string_len(buffer, guess_len, hash);
        attempts++;

        if (attempts % 1000000 == 0) {
            printf("Tried %llu passwords (current: %s)\n", attempts, buffer);
        }

        if (strcmp(hash, target_hash) == 0) {
            time_t end_time = time(NULL);
            printf("\nPassword trovata: %s\n", buffer);
            printf("Tentativi: %llu\n", attempts);
            printf("Tempo: %ld secondi\n", end_time - start_time);
            keep_running = 0;
            return 1;
        }
    }

    return 0;
}

void handle_sigint(int sig) {
    printf("\n❗ Interruzione manuale. Tentativi: %llu\n", attempts);
    keep_running = 0;
}

int main() {
    signal(SIGINT, handle_sigint);

    char input[64];
    printf("Inserisci la tua password da testare (solo lettere a-z): ");
    scanf("%63s", input);

    char target_hash[33];
    md5_string_len(input, strlen(input), target_hash);

    printf("Hash da trovare: %s\n", target_hash);
    printf("Avvio brute-force...\n");

    char buffer[MAX_LEN + 1] = {0};
    time_t start = time(NULL);

    for (int len = 1; len <= MAX_LEN && keep_running; len++) {
        brute_force(buffer, 0, len, target_hash, start);
    }

    if (keep_running) {
        printf("Password non trovata entro la lunghezza massima (%d)\n", MAX_LEN);
    }

    return 0;
}

/* ---------------------- MD5 IMPLEMENTATION ---------------------- */
/* Fonte: https://gist.github.com/creationix/4710780 (modificata) */

#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))
#define MD5STEP(f, w, x, y, z, data, s, ac) \
    (w += f(x, y, z) + data + ac, w = (w << s | w >> (32 - s)) + x)

void md5_init(MD5_CTX *ctx) {
    ctx->h[0] = 0x67452301;
    ctx->h[1] = 0xefcdab89;
    ctx->h[2] = 0x98badcfe;
    ctx->h[3] = 0x10325476;
    ctx->bits[0] = ctx->bits[1] = 0;
}

void md5_update(MD5_CTX *ctx, const uint8 *input, size_t len) {
    uint32 t = ctx->bits[0];
    if ((ctx->bits[0] = t + ((uint32)len << 3)) < t)
        ctx->bits[1]++;
    ctx->bits[1] += (uint32)(len >> 29);

    t = (t >> 3) & 0x3f;

    if (t) {
        uint8 *p = &ctx->buffer[t];
        t = 64 - t;
        if (len < t) {
            memcpy(p, input, len);
            return;
        }
        memcpy(p, input, t);
        md5_transform(ctx->h, ctx->buffer);
        input += t;
        len -= t;
    }

    while (len >= 64) {
        md5_transform(ctx->h, input);
        input += 64;
        len -= 64;
    }

    memcpy(ctx->buffer, input, len);
}

void md5_final(uint8 digest[16], MD5_CTX *ctx) {
    unsigned count = (ctx->bits[0] >> 3) & 0x3F;
    uint8 *p = ctx->buffer + count;
    *p++ = 0x80;
    count = 64 - 1 - count;
    if (count < 8) {
        memset(p, 0, count);
        md5_transform(ctx->h, ctx->buffer);
        memset(ctx->buffer, 0, 56);
    } else {
        memset(p, 0, count - 8);
    }

    ((uint32 *)ctx->buffer)[14] = ctx->bits[0];
    ((uint32 *)ctx->buffer)[15] = ctx->bits[1];

    md5_transform(ctx->h, ctx->buffer);
    for (int i = 0; i < 4; ++i) {
        digest[i*4] = ctx->h[i] & 0xff;
        digest[i*4+1] = (ctx->h[i] >> 8) & 0xff;
        digest[i*4+2] = (ctx->h[i] >> 16) & 0xff;
        digest[i*4+3] = (ctx->h[i] >> 24) & 0xff;
    }
}

void md5_transform(uint32 h[4], const uint8 block[64]) {
    uint32 a = h[0], b = h[1], c = h[2], d = h[3], x[16];

    for (int i = 0; i < 16; ++i) {
        x[i] = ((uint32)block[i*4]) |
               ((uint32)block[i*4+1] << 8) |
               ((uint32)block[i*4+2] << 16) |
               ((uint32)block[i*4+3] << 24);
    }

    MD5STEP(F1, a, b, c, d, x[0], 7, 0xd76aa478);
    MD5STEP(F1, d, a, b, c, x[1], 12, 0xe8c7b756);
    MD5STEP(F1, c, d, a, b, x[2], 17, 0x242070db);
    MD5STEP(F1, b, c, d, a, x[3], 22, 0xc1bdceee);
    MD5STEP(F1, a, b, c, d, x[4], 7, 0xf57c0faf);
    MD5STEP(F1, d, a, b, c, x[5], 12, 0x4787c62a);
    MD5STEP(F1, c, d, a, b, x[6], 17, 0xa8304613);
    MD5STEP(F1, b, c, d, a, x[7], 22, 0xfd469501);
    MD5STEP(F1, a, b, c, d, x[8], 7, 0x698098d8);
    MD5STEP(F1, d, a, b, c, x[9], 12, 0x8b44f7af);
    MD5STEP(F1, c, d, a, b, x[10], 17, 0xffff5bb1);
    MD5STEP(F1, b, c, d, a, x[11], 22, 0x895cd7be);
    MD5STEP(F1, a, b, c, d, x[12], 7, 0x6b901122);
    MD5STEP(F1, d, a, b, c, x[13], 12, 0xfd987193);
    MD5STEP(F1, c, d, a, b, x[14], 17, 0xa679438e);
    MD5STEP(F1, b, c, d, a, x[15], 22, 0x49b40821);

    MD5STEP(F2, a, b, c, d, x[1], 5, 0xf61e2562);
    MD5STEP(F2, d, a, b, c, x[6], 9, 0xc040b340);
    MD5STEP(F2, c, d, a, b, x[11], 14, 0x265e5a51);
    MD5STEP(F2, b, c, d, a, x[0], 20, 0xe9b6c7aa);
    MD5STEP(F2, a, b, c, d, x[5], 5, 0xd62f105d);
    MD5STEP(F2, d, a, b, c, x[10], 9, 0x02441453);
    MD5STEP(F2, c, d, a, b, x[15], 14, 0xd8a1e681);
    MD5STEP(F2, b, c, d, a, x[4], 20, 0xe7d3fbc8);
    MD5STEP(F2, a, b, c, d, x[9], 5, 0x21e1cde6);
    MD5STEP(F2, d, a, b, c, x[14], 9, 0xc33707d6);
    MD5STEP(F2, c, d, a, b, x[3], 14, 0xf4d50d87);
    MD5STEP(F2, b, c, d, a, x[8], 20, 0x455a14ed);
    MD5STEP(F2, a, b, c, d, x[13], 5, 0xa9e3e905);
    MD5STEP(F2, d, a, b, c, x[2], 9, 0xfcefa3f8);
    MD5STEP(F2, c, d, a, b, x[7], 14, 0x676f02d9);
    MD5STEP(F2, b, c, d, a, x[12], 20, 0x8d2a4c8a);

    MD5STEP(F3, a, b, c, d, x[5], 4, 0xfffa3942);
    MD5STEP(F3, d, a, b, c, x[8], 11, 0x8771f681);
    MD5STEP(F3, c, d, a, b, x[11], 16, 0x6d9d6122);
    MD5STEP(F3, b, c, d, a, x[14], 23, 0xfde5380c);
    MD5STEP(F3, a, b, c, d, x[1], 4, 0xa4beea44);
    MD5STEP(F3, d, a, b, c, x[4], 11, 0x4bdecfa9);
    MD5STEP(F3, c, d, a, b, x[7], 16, 0xf6bb4b60);
    MD5STEP(F3, b, c, d, a, x[10], 23, 0xbebfbc70);
    MD5STEP(F3, a, b, c, d, x[13], 4, 0x289b7ec6);
    MD5STEP(F3, d, a, b, c, x[0], 11, 0xeaa127fa);
    MD5STEP(F3, c, d, a, b, x[3], 16, 0xd4ef3085);
    MD5STEP(F3, b, c, d, a, x[6], 23, 0x04881d05);
    MD5STEP(F3, a, b, c, d, x[9], 4, 0xd9d4d039);
    MD5STEP(F3, d, a, b, c, x[12], 11, 0xe6db99e5);
    MD5STEP(F3, c, d, a, b, x[15], 16, 0x1fa27cf8);
    MD5STEP(F3, b, c, d, a, x[2], 23, 0xc4ac5665);

    MD5STEP(F4, a, b, c, d, x[0], 6, 0xf4292244);
    MD5STEP(F4, d, a, b, c, x[7], 10, 0x432aff97);
    MD5STEP(F4, c, d, a, b, x[14], 15, 0xab9423a7);
    MD5STEP(F4, b, c, d, a, x[5], 21, 0xfc93a039);
    MD5STEP(F4, a, b, c, d, x[12], 6, 0x655b59c3);
    MD5STEP(F4, d, a, b, c, x[3], 10, 0x8f0ccc92);
    MD5STEP(F4, c, d, a, b, x[10], 15, 0xffeff47d);
    MD5STEP(F4, b, c, d, a, x[1], 21, 0x85845dd1);
    MD5STEP(F4, a, b, c, d, x[8], 6, 0x6fa87e4f);
    MD5STEP(F4, d, a, b, c, x[15], 10, 0xfe2ce6e0);
    MD5STEP(F4, c, d, a, b, x[6], 15, 0xa3014314);
    MD5STEP(F4, b, c, d, a, x[13], 21, 0x4e0811a1);
    MD5STEP(F4, a, b, c, d, x[4], 6, 0xf7537e82);
    MD5STEP(F4, d, a, b, c, x[11], 10, 0xbd3af235);
    MD5STEP(F4, c, d, a, b, x[2], 15, 0x2ad7d2bb);
    MD5STEP(F4, b, c, d, a, x[9], 21, 0xeb86d391);

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
}
