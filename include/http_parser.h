#ifndef WS_HTTP_PARSER_H
#define WS_HTTP_PARSER_H

#include "util.h"

/* Parse HTTP request line and headers from buffer.
 * Returns bytes consumed, 0 if incomplete, -1 on error.
 * method/path/version are allocated strings (caller must free). */
int ws_http_parse_request(const uint8_t *buf, size_t len,
                          char **method, char **path, char **version,
                          ws_headers_t *headers);

/* Parse HTTP response status line and headers from buffer.
 * Returns bytes consumed, 0 if incomplete, -1 on error. */
int ws_http_parse_response(const uint8_t *buf, size_t len,
                           int *status_code, char **reason,
                           ws_headers_t *headers);

/* Format HTTP response into buffer */
int ws_http_format_response(ws_buf_t *buf, int code, const char *reason,
                            const ws_headers_t *headers);

/* Format HTTP request into buffer */
int ws_http_format_request(ws_buf_t *buf, const char *method, const char *path,
                           const ws_headers_t *headers);

#endif /* WS_HTTP_PARSER_H */
