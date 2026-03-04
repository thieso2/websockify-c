#include "auth_plugins.h"
#include "base64.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ---- BasicHTTPAuth ---- */

typedef struct {
    ws_auth_plugin_t base;
    char *username;
    char *password;
} ws_auth_basic_t;

static void auth_basic_destroy(ws_auth_plugin_t *self)
{
    ws_auth_basic_t *a = (ws_auth_basic_t *)self;
    free(a->username);
    free(a->password);
    free(a->base.source);
    free(a);
}

static int auth_basic_authenticate(ws_auth_plugin_t *self,
                                   const ws_headers_t *headers,
                                   const char *target_host,
                                   const char *target_port,
                                   ws_auth_error_t *err)
{
    ws_auth_basic_t *a = (ws_auth_basic_t *)self;
    (void)target_host;
    (void)target_port;

    const char *auth = ws_headers_get(headers, "Authorization");
    if (!auth || strncmp(auth, "Basic ", 6) != 0) {
        err->code = 401;
        snprintf(err->msg, sizeof(err->msg), "Authentication required");
        strncpy(err->hdr_key, "WWW-Authenticate", sizeof(err->hdr_key) - 1);
        strncpy(err->hdr_val, "Basic realm=\"WebSockify\"", sizeof(err->hdr_val) - 1);
        return -1;
    }

    const char *b64 = auth + 6;
    uint8_t decoded[512];
    int dlen = ws_base64_decode(decoded, sizeof(decoded) - 1, b64, strlen(b64));
    if (dlen < 0) {
        err->code = 403;
        snprintf(err->msg, sizeof(err->msg), "Invalid credentials");
        err->hdr_key[0] = '\0';
        return -1;
    }
    decoded[dlen] = '\0';

    char *colon = strchr((char *)decoded, ':');
    if (!colon) {
        err->code = 403;
        snprintf(err->msg, sizeof(err->msg), "Invalid credentials");
        err->hdr_key[0] = '\0';
        return -1;
    }

    *colon = '\0';
    const char *user = (char *)decoded;
    const char *pass = colon + 1;

    if (strcmp(user, a->username) != 0 || strcmp(pass, a->password) != 0) {
        err->code = 403;
        snprintf(err->msg, sizeof(err->msg), "Invalid credentials");
        err->hdr_key[0] = '\0';
        return -1;
    }

    return 0;
}

ws_auth_plugin_t *ws_auth_basic_new(const char *src)
{
    ws_auth_basic_t *a = calloc(1, sizeof(*a));
    if (!a)
        return NULL;

    a->base.source = strdup(src ? src : "");
    a->base.authenticate = auth_basic_authenticate;
    a->base.destroy = auth_basic_destroy;

    /* Parse "username:password" */
    const char *colon = strchr(src, ':');
    if (colon) {
        a->username = strndup(src, colon - src);
        a->password = strdup(colon + 1);
    } else {
        a->username = strdup(src ? src : "");
        a->password = strdup("");
    }

    return &a->base;
}

/* ---- ExpectOrigin ---- */

typedef struct {
    ws_auth_plugin_t base;
    char **origins;
    int    num_origins;
} ws_auth_origin_t;

static void auth_origin_destroy(ws_auth_plugin_t *self)
{
    ws_auth_origin_t *a = (ws_auth_origin_t *)self;
    for (int i = 0; i < a->num_origins; i++)
        free(a->origins[i]);
    free(a->origins);
    free(a->base.source);
    free(a);
}

static int auth_origin_authenticate(ws_auth_plugin_t *self,
                                    const ws_headers_t *headers,
                                    const char *target_host,
                                    const char *target_port,
                                    ws_auth_error_t *err)
{
    ws_auth_origin_t *a = (ws_auth_origin_t *)self;
    (void)target_host;
    (void)target_port;

    const char *origin = ws_headers_get(headers, "Origin");
    if (!origin) {
        err->code = 403;
        snprintf(err->msg, sizeof(err->msg), "Missing Origin header");
        err->hdr_key[0] = '\0';
        return -1;
    }

    for (int i = 0; i < a->num_origins; i++) {
        if (strcmp(a->origins[i], origin) == 0)
            return 0;
    }

    err->code = 403;
    snprintf(err->msg, sizeof(err->msg), "Origin not allowed: %s", origin);
    err->hdr_key[0] = '\0';
    return -1;
}

ws_auth_plugin_t *ws_auth_expect_origin_new(const char *src)
{
    ws_auth_origin_t *a = calloc(1, sizeof(*a));
    if (!a)
        return NULL;

    a->base.source = strdup(src ? src : "");
    a->base.authenticate = auth_origin_authenticate;
    a->base.destroy = auth_origin_destroy;

    /* Parse whitespace-separated origins */
    if (src) {
        char *copy = strdup(src);
        char *saveptr = NULL;
        /* Count first */
        int count = 0;
        char *tok = strtok_r(copy, " \t\n", &saveptr);
        while (tok) {
            count++;
            tok = strtok_r(NULL, " \t\n", &saveptr);
        }
        free(copy);

        a->origins = calloc(count, sizeof(char *));
        a->num_origins = 0;

        copy = strdup(src);
        tok = strtok_r(copy, " \t\n", &saveptr);
        while (tok && a->num_origins < count) {
            a->origins[a->num_origins++] = strdup(tok);
            tok = strtok_r(NULL, " \t\n", &saveptr);
        }
        free(copy);
    }

    return &a->base;
}

/* ---- ClientCertCNAuth ---- */

typedef struct {
    ws_auth_plugin_t base;
    char **cns;
    int    num_cns;
} ws_auth_certcn_t;

static void auth_certcn_destroy(ws_auth_plugin_t *self)
{
    ws_auth_certcn_t *a = (ws_auth_certcn_t *)self;
    for (int i = 0; i < a->num_cns; i++)
        free(a->cns[i]);
    free(a->cns);
    free(a->base.source);
    free(a);
}

static int auth_certcn_authenticate(ws_auth_plugin_t *self,
                                    const ws_headers_t *headers,
                                    const char *target_host,
                                    const char *target_port,
                                    ws_auth_error_t *err)
{
    ws_auth_certcn_t *a = (ws_auth_certcn_t *)self;
    (void)target_host;
    (void)target_port;

    const char *cn = ws_headers_get(headers, "SSL_CLIENT_S_DN_CN");
    if (!cn) {
        err->code = 403;
        snprintf(err->msg, sizeof(err->msg), "Client certificate required");
        err->hdr_key[0] = '\0';
        return -1;
    }

    for (int i = 0; i < a->num_cns; i++) {
        if (strcmp(a->cns[i], cn) == 0)
            return 0;
    }

    err->code = 403;
    snprintf(err->msg, sizeof(err->msg), "Certificate CN not allowed: %s", cn);
    err->hdr_key[0] = '\0';
    return -1;
}

ws_auth_plugin_t *ws_auth_client_cert_cn_new(const char *src)
{
    ws_auth_certcn_t *a = calloc(1, sizeof(*a));
    if (!a)
        return NULL;

    a->base.source = strdup(src ? src : "");
    a->base.authenticate = auth_certcn_authenticate;
    a->base.destroy = auth_certcn_destroy;

    if (src) {
        char *copy = strdup(src);
        char *saveptr = NULL;
        int count = 0;
        char *tok = strtok_r(copy, " \t\n", &saveptr);
        while (tok) {
            count++;
            tok = strtok_r(NULL, " \t\n", &saveptr);
        }
        free(copy);

        a->cns = calloc(count, sizeof(char *));
        a->num_cns = 0;

        copy = strdup(src);
        tok = strtok_r(copy, " \t\n", &saveptr);
        while (tok && a->num_cns < count) {
            a->cns[a->num_cns++] = strdup(tok);
            tok = strtok_r(NULL, " \t\n", &saveptr);
        }
        free(copy);
    }

    return &a->base;
}
