#ifndef WS_WEBSOCKET_H
#define WS_WEBSOCKET_H

#include "util.h"
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/* WebSocket GUID for handshake */
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/* Opcodes */
#define WS_OPCODE_CONTINUATION 0x0
#define WS_OPCODE_TEXT         0x1
#define WS_OPCODE_BINARY       0x2
#define WS_OPCODE_CLOSE        0x8
#define WS_OPCODE_PING         0x9
#define WS_OPCODE_PONG         0xA

/* Decoded frame */
typedef struct {
    int      fin;
    int      opcode;
    int      masked;
    size_t   length;       /* total frame bytes consumed (header + payload) */
    uint8_t *payload;      /* pointer into decode buffer, valid until next decode */
    size_t   payload_len;
} ws_frame_t;

/* I/O hooks for testability */
typedef struct ws_ctx ws_ctx_t;

typedef ssize_t (*ws_io_send_fn)(ws_ctx_t *ctx, const uint8_t *data, size_t len);
typedef ssize_t (*ws_io_recv_fn)(ws_ctx_t *ctx, uint8_t *data, size_t len);

struct ws_ctx {
    void         *user_data;   /* for fake socket injection in tests */
    ws_io_send_fn io_send;
    ws_io_recv_fn io_recv;
};

/* WebSocket connection state */
typedef struct {
    int          client;         /* 1=client, 0=server */
    ws_buf_t     recv_buf;
    ws_buf_t     send_buf;
    ws_buf_t     partial_msg;
    int          sent_close;
    int          received_close;
    uint16_t     close_code;
    char         close_reason[128];
    ws_ctx_t     ctx;
    /* Subprotocol selection callback (server only) */
    const char *(*select_subprotocol)(const char *protocols);
} ws_conn_t;

/* Initialize/free connection */
void ws_conn_init(ws_conn_t *ws, int client);
void ws_conn_free(ws_conn_t *ws);

/* Frame encode/decode (low-level) */
int ws_decode_hybi(const uint8_t *buf, size_t len, ws_frame_t *frame);
int ws_encode_hybi(int opcode, const uint8_t *payload, size_t payload_len,
                   const uint8_t *mask_key, int fin, ws_buf_t *out);

/* XOR mask/unmask (same operation) */
void ws_mask(uint8_t *buf, size_t len, const uint8_t mask[4]);

/* Handshake */
ws_error_t ws_accept(ws_conn_t *ws, const ws_headers_t *headers);
ws_error_t ws_connect(ws_conn_t *ws, const char *host, const char *path);

/* Send frames */
ws_error_t ws_send(ws_conn_t *ws, const uint8_t *data, size_t len);
ws_error_t ws_sendmsg(ws_conn_t *ws, const uint8_t *data, size_t len);
ws_error_t ws_ping(ws_conn_t *ws, const uint8_t *data, size_t len);
ws_error_t ws_pong(ws_conn_t *ws, const uint8_t *data, size_t len);
ws_error_t ws_shutdown(ws_conn_t *ws, uint16_t code, const char *reason);
ws_error_t ws_close(ws_conn_t *ws);

/* Compute Sec-WebSocket-Accept value */
int ws_compute_accept(const char *key, char *out, size_t out_cap);

#endif /* WS_WEBSOCKET_H */
