#include "websocket.h"
#include "base64.h"
#include "sha1.h"
#include "http_parser.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <arpa/inet.h>

void ws_conn_init(ws_conn_t *ws, int client)
{
    memset(ws, 0, sizeof(*ws));
    ws->client = client;
    ws_buf_init(&ws->recv_buf);
    ws_buf_init(&ws->send_buf);
    ws_buf_init(&ws->partial_msg);
}

void ws_conn_free(ws_conn_t *ws)
{
    ws_buf_free(&ws->recv_buf);
    ws_buf_free(&ws->send_buf);
    ws_buf_free(&ws->partial_msg);
}

/* XOR mask/unmask */
void ws_mask(uint8_t *buf, size_t len, const uint8_t mask[4])
{
    for (size_t i = 0; i < len; i++)
        buf[i] ^= mask[i & 3];
}

int ws_decode_hybi(const uint8_t *buf, size_t len, ws_frame_t *frame)
{
    if (len < 2)
        return 0;

    memset(frame, 0, sizeof(*frame));

    uint8_t b1 = buf[0];
    uint8_t b2 = buf[1];

    frame->fin = (b1 >> 7) & 1;
    frame->opcode = b1 & 0x0F;
    frame->masked = (b2 >> 7) & 1;

    uint64_t payload_len = b2 & 0x7F;
    size_t hlen = 2;

    if (payload_len == 126) {
        if (len < 4)
            return 0;
        payload_len = ((uint64_t)buf[2] << 8) | buf[3];
        hlen = 4;
    } else if (payload_len == 127) {
        if (len < 10)
            return 0;
        payload_len = 0;
        for (int i = 0; i < 8; i++)
            payload_len = (payload_len << 8) | buf[2 + i];
        hlen = 10;
    }

    if (frame->masked)
        hlen += 4;

    if (len < hlen + payload_len)
        return 0;

    frame->payload_len = (size_t)payload_len;
    frame->length = hlen + frame->payload_len;

    /* Point payload at the data portion. Caller must handle unmask. */
    frame->payload = (uint8_t *)(buf + hlen);

    if (frame->masked) {
        const uint8_t *mask_key = buf + hlen - 4;
        /* Unmask in place - we work on a copy in the recv buffer */
        ws_mask(frame->payload, frame->payload_len, mask_key);
    }

    return (int)frame->length;
}

int ws_encode_hybi(int opcode, const uint8_t *payload, size_t payload_len,
                   const uint8_t *mask_key, int fin, ws_buf_t *out)
{
    uint8_t header[14];
    size_t hlen = 2;

    header[0] = (uint8_t)(opcode & 0x0F);
    if (fin)
        header[0] |= 0x80;

    uint8_t mask_bit = mask_key ? 0x80 : 0;

    if (payload_len <= 125) {
        header[1] = (uint8_t)(payload_len | mask_bit);
    } else if (payload_len <= 65535) {
        header[1] = 126 | mask_bit;
        header[2] = (uint8_t)(payload_len >> 8);
        header[3] = (uint8_t)(payload_len);
        hlen = 4;
    } else {
        header[1] = 127 | mask_bit;
        for (int i = 0; i < 8; i++)
            header[2 + i] = (uint8_t)(payload_len >> (56 - i * 8));
        hlen = 10;
    }

    if (ws_buf_append(out, header, hlen) < 0)
        return -1;

    if (mask_key) {
        if (ws_buf_append(out, mask_key, 4) < 0)
            return -1;
        /* Append masked payload */
        size_t start = out->len;
        if (ws_buf_append(out, payload, payload_len) < 0)
            return -1;
        ws_mask(out->data + start, payload_len, mask_key);
    } else {
        if (ws_buf_append(out, payload, payload_len) < 0)
            return -1;
    }

    return 0;
}

int ws_compute_accept(const char *key, char *out, size_t out_cap)
{
    char concat[256];
    int n = snprintf(concat, sizeof(concat), "%s%s", key, WS_GUID);
    if (n < 0 || (size_t)n >= sizeof(concat))
        return -1;

    uint8_t digest[WS_SHA1_DIGEST_SIZE];
    ws_sha1((const uint8_t *)concat, (size_t)n, digest);

    return ws_base64_encode(out, out_cap, digest, WS_SHA1_DIGEST_SIZE);
}

ws_error_t ws_accept(ws_conn_t *ws, const ws_headers_t *headers)
{
    ws->client = 0;

    /* Validate Upgrade header */
    const char *upgrade = ws_headers_get(headers, "upgrade");
    if (!upgrade || strcasecmp(upgrade, "websocket") != 0)
        return WS_ERROR;

    /* Validate version */
    const char *version = ws_headers_get(headers, "Sec-WebSocket-Version");
    if (!version)
        return WS_ERROR;
    int ver = atoi(version);
    if (ver != 7 && ver != 8 && ver != 13)
        return WS_ERROR;

    /* Get key */
    const char *key = ws_headers_get(headers, "Sec-WebSocket-Key");
    if (!key)
        return WS_ERROR;

    /* Handle subprotocol */
    const char *protocols = ws_headers_get(headers, "Sec-WebSocket-Protocol");
    const char *selected_proto = NULL;
    if (protocols) {
        if (ws->select_subprotocol) {
            selected_proto = ws->select_subprotocol(protocols);
        }
        if (!selected_proto)
            return WS_ERROR;
        /* Verify selected is in offered list */
        int found = 0;
        /* Make a mutable copy for tokenizing */
        char *proto_copy = strdup(protocols);
        char *saveptr = NULL;
        char *tok = strtok_r(proto_copy, ", ", &saveptr);
        while (tok) {
            if (strcmp(tok, selected_proto) == 0) {
                found = 1;
                break;
            }
            tok = strtok_r(NULL, ", ", &saveptr);
        }
        free(proto_copy);
        if (!found)
            return WS_ERROR;
    }

    /* Compute accept hash */
    char accept_val[64];
    if (ws_compute_accept(key, accept_val, sizeof(accept_val)) < 0)
        return WS_ERROR;

    /* Build response */
    ws_headers_t resp_headers;
    ws_headers_init(&resp_headers);
    ws_headers_set(&resp_headers, "Upgrade", "websocket");
    ws_headers_set(&resp_headers, "Connection", "Upgrade");
    ws_headers_set(&resp_headers, "Sec-WebSocket-Accept", accept_val);
    if (selected_proto)
        ws_headers_set(&resp_headers, "Sec-WebSocket-Protocol", selected_proto);

    ws_buf_t resp;
    ws_buf_init(&resp);
    ws_http_format_response(&resp, 101, "Switching Protocols", &resp_headers);
    ws_headers_free(&resp_headers);

    /* Send via io_send or buffer */
    if (ws->ctx.io_send) {
        ws->ctx.io_send(&ws->ctx, resp.data, resp.len);
    } else {
        ws_buf_append(&ws->send_buf, resp.data, resp.len);
    }

    ws_buf_free(&resp);
    return WS_OK;
}

ws_error_t ws_connect(ws_conn_t *ws, const char *host, const char *path)
{
    ws->client = 1;
    (void)host;
    (void)path;
    /* TODO: implement client handshake if needed */
    return WS_OK;
}

ws_error_t ws_send(ws_conn_t *ws, const uint8_t *data, size_t len)
{
    ws_buf_t frame;
    ws_buf_init(&frame);
    if (ws_encode_hybi(WS_OPCODE_BINARY, data, len, NULL, 1, &frame) < 0) {
        ws_buf_free(&frame);
        return WS_ERROR;
    }
    if (ws->ctx.io_send) {
        ws->ctx.io_send(&ws->ctx, frame.data, frame.len);
    } else {
        ws_buf_append(&ws->send_buf, frame.data, frame.len);
    }
    ws_buf_free(&frame);
    return WS_OK;
}

ws_error_t ws_sendmsg(ws_conn_t *ws, const uint8_t *data, size_t len)
{
    return ws_send(ws, data, len);
}

ws_error_t ws_ping(ws_conn_t *ws, const uint8_t *data, size_t len)
{
    ws_buf_t frame;
    ws_buf_init(&frame);
    if (ws_encode_hybi(WS_OPCODE_PING, data ? data : (const uint8_t *)"", len, NULL, 1, &frame) < 0) {
        ws_buf_free(&frame);
        return WS_ERROR;
    }
    if (ws->ctx.io_send) {
        ws->ctx.io_send(&ws->ctx, frame.data, frame.len);
    } else {
        ws_buf_append(&ws->send_buf, frame.data, frame.len);
    }
    ws_buf_free(&frame);
    return WS_OK;
}

ws_error_t ws_pong(ws_conn_t *ws, const uint8_t *data, size_t len)
{
    ws_buf_t frame;
    ws_buf_init(&frame);
    if (ws_encode_hybi(WS_OPCODE_PONG, data ? data : (const uint8_t *)"", len, NULL, 1, &frame) < 0) {
        ws_buf_free(&frame);
        return WS_ERROR;
    }
    if (ws->ctx.io_send) {
        ws->ctx.io_send(&ws->ctx, frame.data, frame.len);
    } else {
        ws_buf_append(&ws->send_buf, frame.data, frame.len);
    }
    ws_buf_free(&frame);
    return WS_OK;
}

ws_error_t ws_shutdown(ws_conn_t *ws, uint16_t code, const char *reason)
{
    if (ws->sent_close)
        return WS_OK;
    ws->sent_close = 1;

    uint8_t payload[128];
    size_t plen = 0;
    if (code) {
        payload[0] = (uint8_t)(code >> 8);
        payload[1] = (uint8_t)(code);
        plen = 2;
        if (reason) {
            size_t rlen = strlen(reason);
            if (rlen > sizeof(payload) - 2)
                rlen = sizeof(payload) - 2;
            memcpy(payload + 2, reason, rlen);
            plen += rlen;
        }
    }

    ws_buf_t frame;
    ws_buf_init(&frame);
    ws_encode_hybi(WS_OPCODE_CLOSE, payload, plen, NULL, 1, &frame);
    if (ws->ctx.io_send) {
        ws->ctx.io_send(&ws->ctx, frame.data, frame.len);
    } else {
        ws_buf_append(&ws->send_buf, frame.data, frame.len);
    }
    ws_buf_free(&frame);
    return WS_OK;
}

ws_error_t ws_close(ws_conn_t *ws)
{
    ws_shutdown(ws, 1000, "");
    return WS_CLOSED;
}
