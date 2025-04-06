#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include "md5.h"

#define CHARSET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~"
#define CHARSET_SIZE (sizeof(CHARSET) - 1)
#define MAX_LEN 12

typedef unsigned int uint32;
typedef unsigned char uint8;

volatile int keep_running = 1;
unsigned long long attempts = 0;

int brute_force(char* buffer, int position, int max_len, const uint8* target_digest, time_t start_time) {
    static uint8 digest[16];

    if (!keep_running) return 0;

    for (int i = 0; i < CHARSET_SIZE; i++) {
        if (!keep_running) return 0;

        buffer[position] = CHARSET[i];

        if (position + 1 < max_len) {
            brute_force(buffer, position + 1, max_len, target_digest, start_time);
        }

        buffer[position + 1] = '\0';
        size_t guess_len = position + 1;
        md5_digest(buffer, guess_len, digest);
        attempts++;

        if (attempts % 1000000 == 0) {
            printf("Tried %llu passwords (current: %s)\n", attempts, buffer);
        }

        if (memcmp(digest, target_digest, 16) == 0) {
            time_t end_time = time(NULL);
            printf("\n[FOUND] Password: %s\n", buffer);
            printf("[INFO] Attempts: %llu\n", attempts);
            printf("[INFO] Time: %ld seconds\n", end_time - start_time);
            keep_running = 0;
            return 1;
        }
    }

    return 0;
}

void handle_sigint(int sig) {
    printf("\n[INTERRUPT] Manual stop detected. Attempts: %llu\n", attempts);
    keep_running = 0;
}

int main() {
    signal(SIGINT, handle_sigint);

    char input[64];
    printf("Enter the password you want to test (charset includes a-zA-Z0-9 and symbols): ");
    scanf("%63s", input);

    uint8 target_digest[16];
    md5_digest(input, strlen(input), target_digest);

    printf("[INFO] Brute-force starting from length: %zu\n", strlen(input));

    char buffer[MAX_LEN + 1] = {0};
    time_t start = time(NULL);

    for (int len = strlen(input); len <= MAX_LEN && keep_running; len++) {
        brute_force(buffer, 0, len, target_digest, start);
    }

    if (keep_running) {
        printf("[INFO] Password not found up to length %d\n", MAX_LEN);
    }

    return 0;
}