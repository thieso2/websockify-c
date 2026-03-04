#ifndef WS_BASE64_H
#define WS_BASE64_H

#include <stddef.h>
#include <stdint.h>

/* Returns bytes written to out, or -1 on error. out must be at least ((len+2)/3)*4 + 1. */
int ws_base64_encode(char *out, size_t out_cap, const uint8_t *in, size_t len);

/* Returns bytes written to out, or -1 on error. out must be at least (len/4)*3 + 1. */
int ws_base64_decode(uint8_t *out, size_t out_cap, const char *in, size_t len);

#endif /* WS_BASE64_H */
