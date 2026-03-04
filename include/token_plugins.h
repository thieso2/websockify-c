#ifndef WS_TOKEN_PLUGINS_H
#define WS_TOKEN_PLUGINS_H

#include <stddef.h>

/* Token lookup result */
typedef struct {
    char host[256];
    char port[64];
} ws_target_t;

/* Token plugin vtable */
typedef struct ws_token_plugin ws_token_plugin_t;

struct ws_token_plugin {
    char *source;
    /* Returns 0 on success (fills target), -1 on not found/error */
    int (*lookup)(ws_token_plugin_t *self, const char *token, ws_target_t *target);
    void (*destroy)(ws_token_plugin_t *self);
    void *priv;  /* plugin-private data */
};

/* Parse colon-separated source arguments with quote handling.
 * Returns number of args, fills args[] (caller provides array).
 * Each arg is allocated (caller must free). */
int ws_parse_source_args(const char *src, char **args, int max_args);

/* ReadOnlyTokenFile */
ws_token_plugin_t *ws_token_readonly_file_new(const char *src);

/* TokenFile (reloads on each lookup) */
ws_token_plugin_t *ws_token_file_new(const char *src);

/* TokenFileName (token = filename in directory) */
ws_token_plugin_t *ws_token_filename_new(const char *src);

/* JWTTokenApi */
ws_token_plugin_t *ws_token_jwt_new(const char *src);

/* TokenRedis (requires hiredis) */
ws_token_plugin_t *ws_token_redis_new(const char *src);

/* UnixDomainSocketDirectory */
ws_token_plugin_t *ws_token_unix_dir_new(const char *src);

#endif /* WS_TOKEN_PLUGINS_H */
