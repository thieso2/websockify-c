#include "token_plugins.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>

/* ---- parse_source_args ---- */

int ws_parse_source_args(const char *src, char **args, int max_args)
{
    if (!src || max_args <= 0)
        return 0;

    int argc = 0;
    const char *p = src;
    char buf[4096];
    int blen = 0;
    int in_quote = 0;

    while (*p) {
        if (*p == '"') {
            if (!in_quote) {
                in_quote = 1;
                p++;
                continue;
            } else {
                in_quote = 0;
                p++;
                continue;
            }
        }
        if (*p == ':' && !in_quote) {
            if (argc >= max_args)
                break;
            buf[blen] = '\0';
            args[argc++] = strdup(buf);
            blen = 0;
            p++;
            continue;
        }
        if (blen < (int)sizeof(buf) - 1)
            buf[blen++] = *p;
        p++;
    }
    /* Last segment */
    if (argc < max_args) {
        buf[blen] = '\0';
        args[argc++] = strdup(buf);
    }

    return argc;
}

/* ---- Internal: load token targets from file ---- */

typedef struct {
    char *token;
    char *host;
    char *port;
} ws_token_entry_t;

typedef struct {
    ws_token_entry_t *entries;
    int               count;
    int               cap;
} ws_token_table_t;

static void token_table_init(ws_token_table_t *t)
{
    t->entries = NULL;
    t->count = 0;
    t->cap = 0;
}

static void token_table_free(ws_token_table_t *t)
{
    for (int i = 0; i < t->count; i++) {
        free(t->entries[i].token);
        free(t->entries[i].host);
        free(t->entries[i].port);
    }
    free(t->entries);
    t->entries = NULL;
    t->count = 0;
    t->cap = 0;
}

static int token_table_add(ws_token_table_t *t, const char *token,
                           const char *host, const char *port)
{
    if (t->count >= t->cap) {
        int newcap = t->cap ? t->cap * 2 : 16;
        ws_token_entry_t *e = realloc(t->entries, newcap * sizeof(*e));
        if (!e)
            return -1;
        t->entries = e;
        t->cap = newcap;
    }
    t->entries[t->count].token = strdup(token);
    t->entries[t->count].host = strdup(host);
    t->entries[t->count].port = strdup(port);
    t->count++;
    return 0;
}

static int token_table_lookup(ws_token_table_t *t, const char *token,
                              ws_target_t *target)
{
    for (int i = 0; i < t->count; i++) {
        if (strcmp(t->entries[i].token, token) == 0) {
            snprintf(target->host, sizeof(target->host), "%s", t->entries[i].host);
            snprintf(target->port, sizeof(target->port), "%s", t->entries[i].port);
            return 0;
        }
    }
    return -1;
}

static int load_token_file(const char *path, ws_token_table_t *table)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        /* Strip trailing newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';

        /* Skip empty lines and comments */
        if (len == 0 || line[0] == '#')
            continue;

        /* Split on ": " or ":\t" (colon followed by whitespace) */
        char *sep = NULL;
        for (size_t i = 0; i < len - 1; i++) {
            if (line[i] == ':' && (line[i+1] == ' ' || line[i+1] == '\t')) {
                sep = &line[i];
                break;
            }
        }
        if (!sep)
            continue;

        *sep = '\0';
        char *token = line;
        char *value = sep + 1;
        /* Skip whitespace after colon */
        while (*value == ' ' || *value == '\t')
            value++;

        /* Split value on ':' into host:port */
        char *colon = strchr(value, ':');
        if (colon) {
            *colon = '\0';
            token_table_add(table, token, value, colon + 1);
        }
    }
    fclose(f);
    return 0;
}

static int load_token_dir(const char *path, ws_token_table_t *table)
{
    DIR *d = opendir(path);
    if (!d)
        return -1;

    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.')
            continue;

        char filepath[4096];
        snprintf(filepath, sizeof(filepath), "%s/%s", path, ent->d_name);

        struct stat st;
        if (stat(filepath, &st) < 0)
            continue;
        if (S_ISREG(st.st_mode))
            load_token_file(filepath, table);
    }
    closedir(d);
    return 0;
}

/* ---- ReadOnlyTokenFile ---- */

typedef struct {
    ws_token_plugin_t base;
    ws_token_table_t  table;
    int               loaded;
} ws_token_ro_file_t;

static void ro_file_destroy(ws_token_plugin_t *self)
{
    ws_token_ro_file_t *t = (ws_token_ro_file_t *)self;
    token_table_free(&t->table);
    free(t->base.source);
    free(t);
}

static int ro_file_load(ws_token_ro_file_t *t)
{
    struct stat st;
    if (stat(t->base.source, &st) < 0)
        return -1;
    if (S_ISDIR(st.st_mode))
        return load_token_dir(t->base.source, &t->table);
    else
        return load_token_file(t->base.source, &t->table);
}

static int ro_file_lookup(ws_token_plugin_t *self, const char *token,
                          ws_target_t *target)
{
    ws_token_ro_file_t *t = (ws_token_ro_file_t *)self;
    if (!t->loaded) {
        ro_file_load(t);
        t->loaded = 1;
    }
    return token_table_lookup(&t->table, token, target);
}

ws_token_plugin_t *ws_token_readonly_file_new(const char *src)
{
    ws_token_ro_file_t *t = calloc(1, sizeof(*t));
    if (!t)
        return NULL;
    t->base.source = strdup(src);
    t->base.lookup = ro_file_lookup;
    t->base.destroy = ro_file_destroy;
    token_table_init(&t->table);
    t->loaded = 0;
    return &t->base;
}

/* ---- TokenFile (reloads each time) ---- */

typedef struct {
    ws_token_plugin_t base;
} ws_token_file_t;

static void file_destroy(ws_token_plugin_t *self)
{
    free(self->source);
    free(self);
}

static int file_lookup(ws_token_plugin_t *self, const char *token,
                       ws_target_t *target)
{
    ws_token_table_t table;
    token_table_init(&table);

    struct stat st;
    if (stat(self->source, &st) < 0) {
        token_table_free(&table);
        return -1;
    }

    if (S_ISDIR(st.st_mode))
        load_token_dir(self->source, &table);
    else
        load_token_file(self->source, &table);

    int ret = token_table_lookup(&table, token, target);
    token_table_free(&table);
    return ret;
}

ws_token_plugin_t *ws_token_file_new(const char *src)
{
    ws_token_file_t *t = calloc(1, sizeof(*t));
    if (!t)
        return NULL;
    t->base.source = strdup(src);
    t->base.lookup = file_lookup;
    t->base.destroy = file_destroy;
    return &t->base;
}

/* ---- TokenFileName ---- */

typedef struct {
    ws_token_plugin_t base;
} ws_token_filename_t;

static void filename_destroy(ws_token_plugin_t *self)
{
    free(self->source);
    free(self);
}

static int filename_lookup(ws_token_plugin_t *self, const char *token,
                           ws_target_t *target)
{
    /* Sanitize: use only basename */
    const char *base = strrchr(token, '/');
    base = base ? base + 1 : token;

    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", self->source, base);

    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char line[1024];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);

    /* Strip whitespace */
    size_t len = strlen(line);
    while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' ||
                       line[len-1] == ' ' || line[len-1] == '\t'))
        line[--len] = '\0';

    char *colon = strchr(line, ':');
    if (colon) {
        *colon = '\0';
        snprintf(target->host, sizeof(target->host), "%s", line);
        snprintf(target->port, sizeof(target->port), "%s", colon + 1);
    } else {
        snprintf(target->host, sizeof(target->host), "%s", line);
        target->port[0] = '\0';
    }
    return 0;
}

ws_token_plugin_t *ws_token_filename_new(const char *src)
{
    ws_token_filename_t *t = calloc(1, sizeof(*t));
    if (!t)
        return NULL;
    t->base.source = strdup(src);
    t->base.lookup = filename_lookup;
    t->base.destroy = filename_destroy;
    return &t->base;
}

/* ---- JWTTokenApi ---- */

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

/* Minimal JSON field extractor - find "key":"value" and return value.
 * Only handles string values. Returns allocated string or NULL. */
static char *json_get_string(const char *json, const char *key)
{
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p)
        return NULL;
    p += strlen(pattern);
    while (*p == ' ' || *p == ':')
        p++;
    if (*p != '"')
        return NULL;
    p++;
    const char *end = strchr(p, '"');
    if (!end)
        return NULL;
    return strndup(p, end - p);
}

/* Get integer value from JSON. Returns -1 if not found. */
static long json_get_long(const char *json, const char *key)
{
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p)
        return -1;
    p += strlen(pattern);
    while (*p == ' ' || *p == ':')
        p++;
    return strtol(p, NULL, 10);
}

/* Base64url decode (no padding) */
static int b64url_decode(uint8_t *out, size_t out_cap, const char *in, size_t len)
{
    /* Convert base64url to base64 */
    char *b64 = malloc(len + 4);
    if (!b64)
        return -1;
    for (size_t i = 0; i < len; i++) {
        if (in[i] == '-')
            b64[i] = '+';
        else if (in[i] == '_')
            b64[i] = '/';
        else
            b64[i] = in[i];
    }
    /* Add padding */
    size_t padded = len;
    while (padded % 4 != 0)
        b64[padded++] = '=';
    b64[padded] = '\0';

    int ret = ws_base64_decode(out, out_cap, b64, padded);
    free(b64);
    return ret;
}

typedef struct {
    ws_token_plugin_t base;
} ws_token_jwt_t;

static void jwt_destroy(ws_token_plugin_t *self)
{
    free(self->source);
    free(self);
}

static int jwt_lookup(ws_token_plugin_t *self, const char *token,
                      ws_target_t *target)
{
    /* Split token into header.payload.signature */
    const char *dot1 = strchr(token, '.');
    if (!dot1)
        return -1;
    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2)
        return -1;

    /* Decode header */
    uint8_t hdr_buf[4096];
    int hdr_len = b64url_decode(hdr_buf, sizeof(hdr_buf) - 1, token, dot1 - token);
    if (hdr_len < 0)
        return -1;
    hdr_buf[hdr_len] = '\0';

    char *alg = json_get_string((char *)hdr_buf, "alg");
    if (!alg)
        return -1;

    /* Decode payload */
    uint8_t pay_buf[4096];
    int pay_len = b64url_decode(pay_buf, sizeof(pay_buf) - 1, dot1 + 1, dot2 - dot1 - 1);
    if (pay_len < 0) {
        free(alg);
        return -1;
    }
    pay_buf[pay_len] = '\0';

    /* Decode signature */
    uint8_t sig_buf[512];
    size_t sig_input_len = strlen(dot2 + 1);
    int sig_len = b64url_decode(sig_buf, sizeof(sig_buf), dot2 + 1, sig_input_len);
    if (sig_len < 0) {
        free(alg);
        return -1;
    }

    /* Verify signature */
    size_t signed_len = dot2 - token;
    int verified = 0;

    if (strcmp(alg, "RS256") == 0) {
        /* RSA verification */
        FILE *f = fopen(self->source, "r");
        if (!f) {
            free(alg);
            return -1;
        }
        EVP_PKEY *pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
        if (!pkey) {
            /* Try private key */
            rewind(f);
            pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
        }
        fclose(f);
        if (!pkey) {
            free(alg);
            return -1;
        }

        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
            EVP_DigestVerifyUpdate(mdctx, token, signed_len) == 1 &&
            EVP_DigestVerifyFinal(mdctx, sig_buf, sig_len) == 1) {
            verified = 1;
        }
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
    } else if (strcmp(alg, "HS256") == 0) {
        /* HMAC verification */
        FILE *f = fopen(self->source, "r");
        if (!f) {
            free(alg);
            return -1;
        }
        char secret[4096];
        size_t secret_len = fread(secret, 1, sizeof(secret) - 1, f);
        fclose(f);
        secret[secret_len] = '\0';
        /* Trim whitespace */
        while (secret_len > 0 && (secret[secret_len-1] == '\n' ||
               secret[secret_len-1] == '\r' || secret[secret_len-1] == ' '))
            secret[--secret_len] = '\0';

        /* The secret is base64url-encoded key material */
        uint8_t key_bytes[4096];
        int key_len = b64url_decode(key_bytes, sizeof(key_bytes), secret, secret_len);
        if (key_len < 0) {
            free(alg);
            return -1;
        }

        unsigned int hmac_len = 0;
        uint8_t *hmac_out = HMAC(EVP_sha256(), key_bytes, key_len,
                                 (uint8_t *)token, signed_len,
                                 NULL, &hmac_len);
        if (hmac_out && hmac_len == (unsigned int)sig_len &&
            memcmp(hmac_out, sig_buf, sig_len) == 0) {
            verified = 1;
        }
    }

    free(alg);

    if (!verified)
        return -1;

    /* Check time claims */
    long nbf = json_get_long((char *)pay_buf, "nbf");
    long exp_val = json_get_long((char *)pay_buf, "exp");
    time_t now = time(NULL);

    if (nbf > 0 && now < nbf)
        return -1;
    if (exp_val > 0 && now > exp_val)
        return -1;

    /* Extract host and port */
    char *host = json_get_string((char *)pay_buf, "host");
    char *port = json_get_string((char *)pay_buf, "port");
    if (!host || !port) {
        free(host);
        free(port);
        return -1;
    }

    snprintf(target->host, sizeof(target->host), "%s", host);
    snprintf(target->port, sizeof(target->port), "%s", port);
    free(host);
    free(port);
    return 0;
}

ws_token_plugin_t *ws_token_jwt_new(const char *src)
{
    ws_token_jwt_t *t = calloc(1, sizeof(*t));
    if (!t)
        return NULL;
    t->base.source = strdup(src);
    t->base.lookup = jwt_lookup;
    t->base.destroy = jwt_destroy;
    return &t->base;
}

#else /* !HAVE_OPENSSL */

ws_token_plugin_t *ws_token_jwt_new(const char *src)
{
    (void)src;
    fprintf(stderr, "JWT support requires OpenSSL (compile with -DHAVE_OPENSSL)\n");
    return NULL;
}

#endif /* HAVE_OPENSSL */

/* ---- TokenRedis ---- */

#ifdef HAVE_HIREDIS
#include <hiredis/hiredis.h>
#endif

typedef struct {
    ws_token_plugin_t base;
    char  *server;
    int    port;
    int    db;
    char  *password;
    char  *ns;   /* namespace with trailing colon, or "" */
} ws_token_redis_t;

static void redis_destroy(ws_token_plugin_t *self)
{
    ws_token_redis_t *r = (ws_token_redis_t *)self;
    free(r->server);
    free(r->password);
    free(r->ns);
    free(r->base.source);
    free(r);
}

static int redis_lookup(ws_token_plugin_t *self, const char *token,
                        ws_target_t *target)
{
#ifdef HAVE_HIREDIS
    ws_token_redis_t *r = (ws_token_redis_t *)self;

    redisContext *ctx = redisConnect(r->server, r->port);
    if (!ctx || ctx->err) {
        if (ctx)
            redisFree(ctx);
        return -1;
    }

    if (r->password && r->password[0]) {
        redisReply *reply = redisCommand(ctx, "AUTH %s", r->password);
        if (reply)
            freeReplyObject(reply);
    }

    if (r->db != 0) {
        redisReply *reply = redisCommand(ctx, "SELECT %d", r->db);
        if (reply)
            freeReplyObject(reply);
    }

    char key[512];
    if (r->ns && r->ns[0])
        snprintf(key, sizeof(key), "%s%s", r->ns, token);
    else
        snprintf(key, sizeof(key), "%s", token);

    redisReply *reply = redisCommand(ctx, "GET %s", key);
    if (!reply || reply->type != REDIS_REPLY_STRING) {
        if (reply)
            freeReplyObject(reply);
        redisFree(ctx);
        return -1;
    }

    char *val = strndup(reply->str, reply->len);
    freeReplyObject(reply);
    redisFree(ctx);

    /* Trim whitespace */
    char *v = val;
    while (*v == ' ')
        v++;
    size_t vlen = strlen(v);
    while (vlen > 0 && v[vlen-1] == ' ')
        v[--vlen] = '\0';

    /* Try JSON parse: {"host": "host:port"} */
    if (v[0] == '{') {
        /* Minimal JSON extraction */
        char *host_val = NULL;
        const char *hp = strstr(v, "\"host\"");
        if (hp) {
            hp = strchr(hp + 6, '"');
            if (hp) {
                hp++;
                const char *end = strchr(hp, '"');
                if (end)
                    host_val = strndup(hp, end - hp);
            }
        }
        if (!host_val) {
            free(val);
            return -1;
        }
        char *colon = strchr(host_val, ':');
        if (colon) {
            *colon = '\0';
            snprintf(target->host, sizeof(target->host), "%s", host_val);
            snprintf(target->port, sizeof(target->port), "%s", colon + 1);
        } else {
            snprintf(target->host, sizeof(target->host), "%s", host_val);
            target->port[0] = '\0';
        }
        free(host_val);
    } else {
        /* Plain text: host:port */
        char *colon = strchr(v, ':');
        if (colon) {
            *colon = '\0';
            snprintf(target->host, sizeof(target->host), "%s", v);
            snprintf(target->port, sizeof(target->port), "%s", colon + 1);
        } else {
            snprintf(target->host, sizeof(target->host), "%s", v);
            target->port[0] = '\0';
        }
    }

    free(val);
    return 0;
#else
    (void)self;
    (void)token;
    (void)target;
    return -1;
#endif
}

ws_token_plugin_t *ws_token_redis_new(const char *src)
{
    ws_token_redis_t *r = calloc(1, sizeof(*r));
    if (!r)
        return NULL;

    r->base.source = strdup(src);
    r->base.lookup = redis_lookup;
    r->base.destroy = redis_destroy;

    /* Parse source: host[:port[:db[:password[:namespace]]]] */
    char *args[6] = {NULL};
    int argc = ws_parse_source_args(src, args, 6);

    r->server = (argc > 0 && args[0][0]) ? strdup(args[0]) : strdup("127.0.0.1");
    r->port = (argc > 1 && args[1][0]) ? atoi(args[1]) : 6379;
    r->db = (argc > 2 && args[2][0]) ? atoi(args[2]) : 0;
    r->password = (argc > 3 && args[3][0]) ? strdup(args[3]) : NULL;

    if (argc > 4 && args[4][0]) {
        /* Append trailing colon to namespace */
        size_t nlen = strlen(args[4]);
        r->ns = malloc(nlen + 2);
        memcpy(r->ns, args[4], nlen);
        r->ns[nlen] = ':';
        r->ns[nlen + 1] = '\0';
    } else {
        r->ns = strdup("");
    }

    for (int i = 0; i < argc; i++)
        free(args[i]);

    return &r->base;
}

/* ---- UnixDomainSocketDirectory ---- */

typedef struct {
    ws_token_plugin_t base;
} ws_token_unix_dir_t;

static void unix_dir_destroy(ws_token_plugin_t *self)
{
    free(self->source);
    free(self);
}

static int unix_dir_lookup(ws_token_plugin_t *self, const char *token,
                           ws_target_t *target)
{
    /* Sanitize path to prevent directory traversal */
    const char *base = strrchr(token, '/');
    base = base ? base + 1 : token;

    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", self->source, base);

    struct stat st;
    if (stat(path, &st) < 0)
        return -1;
    if (!S_ISSOCK(st.st_mode))
        return -1;

    snprintf(target->host, sizeof(target->host), "unix_socket");
    snprintf(target->port, sizeof(target->port), "%s", path);
    return 0;
}

ws_token_plugin_t *ws_token_unix_dir_new(const char *src)
{
    ws_token_unix_dir_t *t = calloc(1, sizeof(*t));
    if (!t)
        return NULL;
    t->base.source = strdup(src);
    t->base.lookup = unix_dir_lookup;
    t->base.destroy = unix_dir_destroy;
    return &t->base;
}
