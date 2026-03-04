#ifndef WS_SHA1_H
#define WS_SHA1_H

#include <stddef.h>
#include <stdint.h>

#define WS_SHA1_DIGEST_SIZE 20
#define WS_SHA1_BLOCK_SIZE  64

typedef struct {
    uint32_t state[5];
    uint64_t count;
    uint8_t  buffer[WS_SHA1_BLOCK_SIZE];
} ws_sha1_ctx;

void ws_sha1_init(ws_sha1_ctx *ctx);
void ws_sha1_update(ws_sha1_ctx *ctx, const uint8_t *data, size_t len);
void ws_sha1_final(ws_sha1_ctx *ctx, uint8_t digest[WS_SHA1_DIGEST_SIZE]);

/* One-shot convenience */
void ws_sha1(const uint8_t *data, size_t len, uint8_t digest[WS_SHA1_DIGEST_SIZE]);

#endif /* WS_SHA1_H */
