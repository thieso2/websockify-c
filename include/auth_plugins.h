#ifndef WS_AUTH_PLUGINS_H
#define WS_AUTH_PLUGINS_H

#include "util.h"

/* Authentication error */
typedef struct {
    int   code;          /* HTTP response code (401, 403) */
    char  msg[256];      /* error message */
    char  hdr_key[64];   /* optional response header key */
    char  hdr_val[256];  /* optional response header value */
} ws_auth_error_t;

/* Auth plugin vtable */
typedef struct ws_auth_plugin ws_auth_plugin_t;

struct ws_auth_plugin {
    char *source;
    /* Returns 0 on success, fills err and returns -1 on failure */
    int (*authenticate)(ws_auth_plugin_t *self, const ws_headers_t *headers,
                        const char *target_host, const char *target_port,
                        ws_auth_error_t *err);
    void (*destroy)(ws_auth_plugin_t *self);
};

/* BasicHTTPAuth */
ws_auth_plugin_t *ws_auth_basic_new(const char *src);

/* ExpectOrigin */
ws_auth_plugin_t *ws_auth_expect_origin_new(const char *src);

/* ClientCertCNAuth */
ws_auth_plugin_t *ws_auth_client_cert_cn_new(const char *src);

#endif /* WS_AUTH_PLUGINS_H */
