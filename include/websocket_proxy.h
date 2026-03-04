#ifndef WS_WEBSOCKET_PROXY_H
#define WS_WEBSOCKET_PROXY_H

#include "websockify_server.h"
#include "websocket.h"

/* Target lookup via token plugin */
int ws_proxy_get_target(ws_server_t *srv, const char *path,
                        const ws_headers_t *headers,
                        char *host, size_t host_len,
                        char *port, size_t port_len);

/* Validate connection (token resolution) */
int ws_proxy_validate_connection(ws_server_t *srv, const char *path,
                                 const ws_headers_t *headers);

/* Auth connection */
int ws_proxy_auth_connection(ws_server_t *srv, const ws_headers_t *headers);

/* Main bidirectional proxy loop */
int ws_proxy_do_proxy(ws_conn_t *ws_client, int target_fd,
                      int heartbeat_interval);

/* Handle a new WebSocket client (called after handshake) */
int ws_proxy_new_client(ws_server_t *srv, ws_conn_t *ws, int client_fd);

#endif /* WS_WEBSOCKET_PROXY_H */
