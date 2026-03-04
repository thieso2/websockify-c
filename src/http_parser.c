#include "http_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Find \r\n\r\n in buffer. Returns offset past it, or 0 if not found. */
static size_t find_header_end(const uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' &&
            buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return i + 4;
        }
    }
    return 0;
}

/* Find CRLF within [p, end). Returns pointer to '\r' or NULL. */
static const char *find_crlf(const char *p, const char *end)
{
    const char *cur = p;
    while (cur + 1 < end) {
        if (cur[0] == '\r' && cur[1] == '\n') {
            return cur;
        }
        cur++;
    }
    return NULL;
}

/* Parse a single header line "Key: Value" (no trailing CRLF) */
static int parse_header_line(const char *line, size_t len, ws_headers_t *h)
{
    const char *colon = memchr(line, ':', len);
    const char *vstart;
    size_t klen;
    size_t vlen;
    char key[256];
    char val[4096];

    if (!colon) {
        return -1;
    }

    klen = (size_t)(colon - line);
    vstart = colon + 1;
    vlen = len - klen - 1;

    while (vlen > 0 && (*vstart == ' ' || *vstart == '\t')) {
        vstart++;
        vlen--;
    }
    while (vlen > 0 && (vstart[vlen - 1] == ' ' || vstart[vlen - 1] == '\t')) {
        vlen--;
    }

    if (klen >= sizeof(key) || vlen >= sizeof(val)) {
        return -1;
    }

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
    size_t end_off = find_header_end(buf, len);
    const char *start;
    const char *end;
    const char *line_end;
    const char *sp1;
    const char *sp2;
    const char *p;

    if (end_off == 0) {
        return 0;
    }

    start = (const char *)buf;
    end = start + end_off;

    line_end = find_crlf(start, end);
    if (!line_end) {
        return -1;
    }

    sp1 = memchr(start, ' ', (size_t)(line_end - start));
    if (!sp1) {
        return -1;
    }
    sp2 = memchr(sp1 + 1, ' ', (size_t)(line_end - (sp1 + 1)));
    if (!sp2) {
        return -1;
    }

    *method = strndup(start, (size_t)(sp1 - start));
    *path = strndup(sp1 + 1, (size_t)(sp2 - (sp1 + 1)));
    *version = strndup(sp2 + 1, (size_t)(line_end - (sp2 + 1)));
    if (!*method || !*path || !*version) {
        free(*method);
        free(*path);
        free(*version);
        *method = NULL;
        *path = NULL;
        *version = NULL;
        return -1;
    }

    ws_headers_init(headers);
    p = line_end + 2;
    while (p < end - 2) {
        const char *next = find_crlf(p, end);
        if (!next || next == p) {
            break;
        }
        if (parse_header_line(p, (size_t)(next - p), headers) < 0) {
            return -1;
        }
        p = next + 2;
    }

    return (int)end_off;
}

int ws_http_parse_response(const uint8_t *buf, size_t len,
                           int *status_code, char **reason,
                           ws_headers_t *headers)
{
    size_t end_off = find_header_end(buf, len);
    const char *start;
    const char *end;
    const char *line_end;
    const char *sp1;
    const char *sp2;
    const char *p;

    if (end_off == 0) {
        return 0;
    }

    start = (const char *)buf;
    end = start + end_off;

    line_end = find_crlf(start, end);
    if (!line_end) {
        return -1;
    }

    sp1 = memchr(start, ' ', (size_t)(line_end - start));
    if (!sp1) {
        return -1;
    }

    *status_code = atoi(sp1 + 1);

    sp2 = memchr(sp1 + 1, ' ', (size_t)(line_end - (sp1 + 1)));
    if (sp2) {
        *reason = strndup(sp2 + 1, (size_t)(line_end - (sp2 + 1)));
    } else {
        *reason = strdup("");
    }
    if (!*reason) {
        return -1;
    }

    ws_headers_init(headers);
    p = line_end + 2;
    while (p < end - 2) {
        const char *next = find_crlf(p, end);
        if (!next || next == p) {
            break;
        }
        if (parse_header_line(p, (size_t)(next - p), headers) < 0) {
            return -1;
        }
        p = next + 2;
    }

    return (int)end_off;
}

int ws_http_format_response(ws_buf_t *buf, int code, const char *reason,
                            const ws_headers_t *headers)
{
    char line[256];
    int i;
    int n = snprintf(line, sizeof(line), "HTTP/1.1 %d %s\r\n", code, reason ? reason : "");
    if (ws_buf_append(buf, (uint8_t *)line, (size_t)n) < 0) {
        return -1;
    }

    if (headers) {
        for (i = 0; i < headers->count; i++) {
            n = snprintf(line, sizeof(line), "%s: %s\r\n", headers->keys[i], headers->vals[i]);
            if (ws_buf_append(buf, (uint8_t *)line, (size_t)n) < 0) {
                return -1;
            }
        }
    }

    return ws_buf_append(buf, (uint8_t *)"\r\n", 2);
}

int ws_http_format_request(ws_buf_t *buf, const char *method, const char *path,
                           const ws_headers_t *headers)
{
    char line[4096];
    int i;
    int n = snprintf(line, sizeof(line), "%s %s HTTP/1.1\r\n", method, path);
    if (ws_buf_append(buf, (uint8_t *)line, (size_t)n) < 0) {
        return -1;
    }

    if (headers) {
        for (i = 0; i < headers->count; i++) {
            n = snprintf(line, sizeof(line), "%s: %s\r\n", headers->keys[i], headers->vals[i]);
            if (ws_buf_append(buf, (uint8_t *)line, (size_t)n) < 0) {
                return -1;
            }
        }
    }

    return ws_buf_append(buf, (uint8_t *)"\r\n", 2);
}
