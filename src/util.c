#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ws_buf_t */

void ws_buf_init(ws_buf_t *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void ws_buf_free(ws_buf_t *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

int ws_buf_reserve(ws_buf_t *b, size_t additional)
{
    size_t need = b->len + additional;
    if (need <= b->cap)
        return 0;
    size_t newcap = b->cap ? b->cap : 64;
    while (newcap < need)
        newcap *= 2;
    uint8_t *p = realloc(b->data, newcap);
    if (!p)
        return -1;
    b->data = p;
    b->cap = newcap;
    return 0;
}

int ws_buf_append(ws_buf_t *b, const uint8_t *data, size_t len)
{
    if (ws_buf_reserve(b, len) < 0)
        return -1;
    memcpy(b->data + b->len, data, len);
    b->len += len;
    return 0;
}

void ws_buf_consume(ws_buf_t *b, size_t n)
{
    if (n >= b->len) {
        b->len = 0;
        return;
    }
    memmove(b->data, b->data + n, b->len - n);
    b->len -= n;
}

void ws_buf_clear(ws_buf_t *b)
{
    b->len = 0;
}

/* ws_headers_t */

void ws_headers_init(ws_headers_t *h)
{
    h->count = 0;
    memset(h->keys, 0, sizeof(h->keys));
    memset(h->vals, 0, sizeof(h->vals));
}

void ws_headers_free(ws_headers_t *h)
{
    for (int i = 0; i < h->count; i++) {
        free(h->keys[i]);
        free(h->vals[i]);
    }
    h->count = 0;
}

const char *ws_headers_get(const ws_headers_t *h, const char *key)
{
    for (int i = 0; i < h->count; i++) {
        if (strcasecmp(h->keys[i], key) == 0)
            return h->vals[i];
    }
    return NULL;
}

int ws_headers_set(ws_headers_t *h, const char *key, const char *val)
{
    for (int i = 0; i < h->count; i++) {
        if (strcasecmp(h->keys[i], key) == 0) {
            char *v = strdup(val);
            if (!v)
                return -1;
            free(h->vals[i]);
            h->vals[i] = v;
            return 0;
        }
    }
    if (h->count >= WS_HEADERS_MAX)
        return -1;
    char *k = strdup(key);
    char *v = strdup(val);
    if (!k || !v) {
        free(k);
        free(v);
        return -1;
    }
    h->keys[h->count] = k;
    h->vals[h->count] = v;
    h->count++;
    return 0;
}

int ws_headers_del(ws_headers_t *h, const char *key)
{
    for (int i = 0; i < h->count; i++) {
        if (strcasecmp(h->keys[i], key) == 0) {
            free(h->keys[i]);
            free(h->vals[i]);
            /* shift remaining */
            for (int j = i; j < h->count - 1; j++) {
                h->keys[j] = h->keys[j + 1];
                h->vals[j] = h->vals[j + 1];
            }
            h->count--;
            return 0;
        }
    }
    return -1;
}
