#ifndef WS_UTIL_H
#define WS_UTIL_H

#include <stddef.h>
#include <stdint.h>

/* Dynamic byte buffer */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} ws_buf_t;

void    ws_buf_init(ws_buf_t *b);
void    ws_buf_free(ws_buf_t *b);
int     ws_buf_append(ws_buf_t *b, const uint8_t *data, size_t len);
void    ws_buf_consume(ws_buf_t *b, size_t n);
void    ws_buf_clear(ws_buf_t *b);
int     ws_buf_reserve(ws_buf_t *b, size_t additional);

/* Case-insensitive header map */
#define WS_HEADERS_MAX 64

typedef struct {
    char *keys[WS_HEADERS_MAX];
    char *vals[WS_HEADERS_MAX];
    int   count;
} ws_headers_t;

void        ws_headers_init(ws_headers_t *h);
void        ws_headers_free(ws_headers_t *h);
const char *ws_headers_get(const ws_headers_t *h, const char *key);
int         ws_headers_set(ws_headers_t *h, const char *key, const char *val);
int         ws_headers_del(ws_headers_t *h, const char *key);

/* Error codes */
typedef enum {
    WS_OK = 0,
    WS_WANT_READ,
    WS_WANT_WRITE,
    WS_ERROR,
    WS_CLOSED
} ws_error_t;

#endif /* WS_UTIL_H */
