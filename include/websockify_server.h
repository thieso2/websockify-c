#ifndef WS_WEBSOCKIFY_SERVER_H
#define WS_WEBSOCKIFY_SERVER_H

#include "util.h"
#include "websocket.h"
#include "auth_plugins.h"
#include "token_plugins.h"
#include <sys/types.h>

/* Server configuration */
typedef struct {
    char  *listen_host;
    int    listen_port;
    char  *cert;
    char  *key;
    char  *cafile;
    char  *web;
    char  *record;
    int    daemon;
    int    ssl_only;
    int    run_once;
    int    verbose;
    int    idle_timeout;
    int    file_only;
    int    traffic;
    char  *ssl_ciphers;
    unsigned int ssl_options;
    int    tcp_keepalive;
    int    tcp_keepcnt;
    int    tcp_keepidle;
    int    tcp_keepintvl;
    ws_auth_plugin_t  *auth_plugin;
    ws_token_plugin_t *token_plugin;
    int    host_token;
    /* Runtime state */
    int    terminating;
    int    handler_id;
    int    ws_connection;
    char  *target_host;
    int    target_port;
    char  *unix_target;
    int    ssl_target;
    int    heartbeat;
    char  *wrap_cmd;
    char  *wrap_mode;
} ws_server_t;

/* Initialize server with defaults */
void ws_server_init(ws_server_t *srv);
void ws_server_free(ws_server_t *srv);

/* Start listening and serving */
int ws_server_start(ws_server_t *srv);

/* Daemonize */
int ws_server_daemonize(int *keepfds, int nkeepfds, const char *chdir_to);

/* Do handshake on accepted socket. Returns new fd (may be SSL-wrapped), or -1. */
int ws_server_do_handshake(ws_server_t *srv, int sock, const char *addr,
                           int *is_ssl);

/* Create a connected or listening socket */
int ws_server_socket(const char *host, int port, int do_connect, int prefer_ipv6,
                     const char *unix_socket, int tcp_keepalive,
                     int tcp_keepcnt, int tcp_keepidle, int tcp_keepintvl);

/* HTTP error response */
void ws_server_send_error(int fd, int code, const char *msg);

/* HTTP method checks - return non-zero if method not allowed */
int ws_server_check_method(const char *method, int has_web);

#endif /* WS_WEBSOCKIFY_SERVER_H */
