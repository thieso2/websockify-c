#include "http_parser.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Find \r\n\r\n in buffer. Returns offset past it, or 0 if not found. */
static size_t find_header_end(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n' &&
            buf[i+2] == '\r' && buf[i+3] == '\n')
            return i + 4;
    }
    return 0;
}

/* Parse a single header line "Key: Value\r\n" */
static int parse_header_line(const char *line, size_t len, ws_headers_t *h)
{
    const char *colon = memchr(line, ':', len);
    if (!colon)
        return -1;
    size_t klen = colon - line;
    const char *vstart = colon + 1;
    size_t vlen = len - klen - 1;
    while (vlen > 0 && (*vstart == ' ' || *vstart == '\t')) {
        vstart++;
        vlen--;
    }
    while (vlen > 0 && (vstart[vlen-1] == ' ' || vstart[vlen-1] == '\t'))
        vlen--;

    char key[256], val[4096];
    if (klen >= sizeof(key) || vlen >= sizeof(val))
        return -1;
    memcpy(key, line, klen);
    key[klen] = '\0';
    memcpy(val, vstart, vlen);
    val[vlen] = '\0';

    return ws_headers_set(h, key, val);
}

int ws_http_parse_request(const uint8_t *buf, size_t len,
                          char **method, char **path, char **version,
                          ws_headers_t *headers)
{
    size_t end = find_header_end(buf, len);
    if (end == 0)
        return 0;

    const char *s = (const char *)buf;

    /* Parse request line */
    const char *line_end = strstr(s, "\r\n");
    if (!line_end)
        return -1;

    /* METHOD SP PATH SP VERSION */
    const char *sp1 = memchr(s, ' ', line_end - s);
    if (!sp1)
        return -1;
    const char *sp2 = memchr(sp1 + 1, ' ', line_end - sp1 - 1);
    if (!sp2)
        return -1;

    *method = strndup(s, sp1 - s);
    *path = strndup(sp1 + 1, sp2 - sp1 - 1);
    *version = strndup(sp2 + 1, line_end - sp2 - 1);

    /* Parse headers */
    ws_headers_init(headers);
    const char *p = line_end + 2;
    while (p < (const char *)buf + end - 2) {
        const char *next = strstr(p, "\r\n");
        if (!next)
            break;
        if (next == p)
            break;
        parse_header_line(p, next - p, headers);
        p = next + 2;
    }

    return (int)end;
}

int ws_http_parse_response(const uint8_t *buf, size_t len,
                           int *status_code, char **reason,
                           ws_headers_t *headers)
{
    size_t end = find_header_end(buf, len);
    if (end == 0)
        return 0;

    const char *s = (const char *)buf;
    const char *line_end = strstr(s, "\r\n");
    if (!line_end)
        return -1;

    /* HTTP/1.1 CODE REASON */
    const char *sp1 = memchr(s, ' ', line_end - s);
    if (!sp1)
        return -1;
    *status_code = atoi(sp1 + 1);
    const char *sp2 = memchr(sp1 + 1, ' ', line_end - sp1 - 1);
    if (sp2)
        *reason = strndup(sp2 + 1, line_end - sp2 - 1);
    else
        *reason = strdup("");

    ws_headers_init(headers);
    const char *p = line_end + 2;
    while (p < (const char *)buf + end - 2) {
        const char *next = strstr(p, "\r\n");
        if (!next)
            break;
        if (next == p)
            break;
        parse_header_line(p, next - p, headers);
        p = next + 2;
    }

    return (int)end;
}

int ws_http_format_response(ws_buf_t *buf, int code, const char *reason,
                            const ws_headers_t *headers)
{
    char line[256];
    int n = snprintf(line, sizeof(line), "HTTP/1.1 %d %s\r\n", code, reason ? reason : "");
    if (ws_buf_append(buf, (uint8_t *)line, n) < 0)
        return -1;
    if (headers) {
        for (int i = 0; i < headers->count; i++) {
            n = snprintf(line, sizeof(line), "%s: %s\r\n", headers->keys[i], headers->vals[i]);
            if (ws_buf_append(buf, (uint8_t *)line, n) < 0)
                return -1;
        }
    }
    return ws_buf_append(buf, (uint8_t *)"\r\n", 2);
}

int ws_http_format_request(ws_buf_t *buf, const char *method, const char *path,
                           const ws_headers_t *headers)
{
    char line[4096];
    int n = snprintf(line, sizeof(line), "%s %s HTTP/1.1\r\n", method, path);
    if (ws_buf_append(buf, (uint8_t *)line, n) < 0)
        return -1;
    if (headers) {
        for (int i = 0; i < headers->count; i++) {
            n = snprintf(line, sizeof(line), "%s: %s\r\n", headers->keys[i], headers->vals[i]);
            if (ws_buf_append(buf, (uint8_t *)line, n) < 0)
                return -1;
        }
    }
    return ws_buf_append(buf, (uint8_t *)"\r\n", 2);
}
