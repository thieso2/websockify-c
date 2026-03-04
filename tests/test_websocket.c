#include "test_common.h"
#include "websocket.h"
#include "util.h"

#include <stdint.h>
#include <string.h>

static const char *g_select_mode = NULL;

static const char *test_select_subprotocol(const char *protocols)
{
    (void)protocols;
    if (g_select_mode == NULL) {
        return NULL;
    }
    return g_select_mode;
}

static int contains_bytes(const uint8_t *hay, size_t hay_len, const char *needle)
{
    size_t i;
    size_t nlen = strlen(needle);
    if (nlen == 0 || nlen > hay_len) {
        return 0;
    }
    for (i = 0; i + nlen <= hay_len; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) {
            return 1;
        }
    }
    return 0;
}

static void setup_accept_headers(ws_headers_t *headers)
{
    ws_headers_init(headers);
    ws_headers_set(headers, "upgrade", "websocket");
    ws_headers_set(headers, "Sec-WebSocket-Version", "13");
    ws_headers_set(headers, "Sec-WebSocket-Key", "DKURYVK9cRFul1vOZVA56Q==");
}

TEST(test_accept_success)
{
    ws_conn_t ws;
    ws_headers_t headers;

    ws_conn_init(&ws, 0);
    setup_accept_headers(&headers);

    ASSERT_EQ(ws_accept(&ws, &headers), WS_OK);
    ASSERT(ws.send_buf.len >= 13);
    ASSERT_MEM_EQ(ws.send_buf.data, "HTTP/1.1 101 ", 13);
    ASSERT(contains_bytes(ws.send_buf.data, ws.send_buf.len, "\r\nUpgrade: websocket\r\n"));
    ASSERT(contains_bytes(ws.send_buf.data, ws.send_buf.len, "\r\nConnection: Upgrade\r\n"));
    ASSERT(contains_bytes(ws.send_buf.data, ws.send_buf.len, "\r\nSec-WebSocket-Accept: pczpYSQsvE1vBpTQYjFQPcuoj6M=\r\n"));

    ws_headers_free(&headers);
    ws_conn_free(&ws);
}

TEST(test_accept_bad_version)
{
    ws_conn_t ws;
    ws_headers_t headers;

    ws_conn_init(&ws, 0);
    ws_headers_init(&headers);
    ws_headers_set(&headers, "upgrade", "websocket");
    ws_headers_set(&headers, "Sec-WebSocket-Key", "DKURYVK9cRFul1vOZVA56Q==");
    ASSERT_EQ(ws_accept(&ws, &headers), WS_ERROR);

    ws_headers_set(&headers, "Sec-WebSocket-Version", "5");
    ASSERT_EQ(ws_accept(&ws, &headers), WS_ERROR);

    ws_headers_set(&headers, "Sec-WebSocket-Version", "20");
    ASSERT_EQ(ws_accept(&ws, &headers), WS_ERROR);

    ws_headers_free(&headers);
    ws_conn_free(&ws);
}

TEST(test_accept_bad_upgrade)
{
    ws_conn_t ws;
    ws_headers_t headers;

    ws_conn_init(&ws, 0);
    ws_headers_init(&headers);
    ws_headers_set(&headers, "Sec-WebSocket-Version", "13");
    ws_headers_set(&headers, "Sec-WebSocket-Key", "DKURYVK9cRFul1vOZVA56Q==");
    ASSERT_EQ(ws_accept(&ws, &headers), WS_ERROR);

    ws_headers_set(&headers, "upgrade", "websocket2");
    ASSERT_EQ(ws_accept(&ws, &headers), WS_ERROR);

    ws_headers_free(&headers);
    ws_conn_free(&ws);
}

TEST(test_accept_missing_key)
{
    ws_conn_t ws;
    ws_headers_t headers;

    ws_conn_init(&ws, 0);
    ws_headers_init(&headers);
    ws_headers_set(&headers, "upgrade", "websocket");
    ws_headers_set(&headers, "Sec-WebSocket-Version", "13");

    ASSERT_EQ(ws_accept(&ws, &headers), WS_ERROR);

    ws_headers_free(&headers);
    ws_conn_free(&ws);
}

TEST(test_accept_protocol)
{
    ws_conn_t ws;
    ws_headers_t headers;

    ws_conn_init(&ws, 0);
    ws.select_subprotocol = test_select_subprotocol;
    g_select_mode = "gazonk";

    setup_accept_headers(&headers);
    ws_headers_set(&headers, "Sec-WebSocket-Protocol", "foobar,gazonk");

    ASSERT_EQ(ws_accept(&ws, &headers), WS_OK);
    ASSERT(contains_bytes(ws.send_buf.data, ws.send_buf.len, "\r\nSec-WebSocket-Protocol: gazonk\r\n"));

    ws_headers_free(&headers);
    ws_conn_free(&ws);
}

TEST(test_accept_no_protocol)
{
    ws_conn_t ws;
    ws_headers_t headers;

    ws_conn_init(&ws, 0);
    setup_accept_headers(&headers);

    ASSERT_EQ(ws_accept(&ws, &headers), WS_OK);
    ASSERT(!contains_bytes(ws.send_buf.data, ws.send_buf.len, "\r\nSec-WebSocket-Protocol:"));

    ws_headers_free(&headers);
    ws_conn_free(&ws);
}

TEST(test_accept_missing_protocol_handler)
{
    ws_conn_t ws;
    ws_headers_t headers;

    ws_conn_init(&ws, 0);
    setup_accept_headers(&headers);
    ws_headers_set(&headers, "Sec-WebSocket-Protocol", "foobar,gazonk");

    ASSERT_EQ(ws_accept(&ws, &headers), WS_ERROR);

    ws_headers_free(&headers);
    ws_conn_free(&ws);
}

TEST(test_accept_unsupported_protocol)
{
    ws_conn_t ws;
    ws_headers_t headers;

    ws_conn_init(&ws, 0);
    ws.select_subprotocol = test_select_subprotocol;
    g_select_mode = "oddball";

    setup_accept_headers(&headers);
    ws_headers_set(&headers, "Sec-WebSocket-Protocol", "foobar,gazonk");

    ASSERT_EQ(ws_accept(&ws, &headers), WS_ERROR);

    ws_headers_free(&headers);
    ws_conn_free(&ws);
}

static void setup_accepted_connection(ws_conn_t *ws)
{
    ws_headers_t headers;

    ws_conn_init(ws, 0);
    setup_accept_headers(&headers);
    ASSERT_EQ(ws_accept(ws, &headers), WS_OK);
    ws_buf_clear(&ws->send_buf);

    ws_headers_free(&headers);
}

TEST(test_ping)
{
    ws_conn_t ws;
    const uint8_t expected[] = {0x89, 0x00};

    setup_accepted_connection(&ws);
    ASSERT_EQ(ws_ping(&ws, NULL, 0), WS_OK);
    ASSERT_EQ(ws.send_buf.len, sizeof(expected));
    ASSERT_MEM_EQ(ws.send_buf.data, expected, sizeof(expected));

    ws_conn_free(&ws);
}

TEST(test_pong)
{
    ws_conn_t ws;
    const uint8_t expected[] = {0x8a, 0x00};

    setup_accepted_connection(&ws);
    ASSERT_EQ(ws_pong(&ws, NULL, 0), WS_OK);
    ASSERT_EQ(ws.send_buf.len, sizeof(expected));
    ASSERT_MEM_EQ(ws.send_buf.data, expected, sizeof(expected));

    ws_conn_free(&ws);
}

TEST(test_ping_data)
{
    ws_conn_t ws;
    const uint8_t expected[] = {0x89, 0x03, 'f', 'o', 'o'};

    setup_accepted_connection(&ws);
    ASSERT_EQ(ws_ping(&ws, (const uint8_t *)"foo", 3), WS_OK);
    ASSERT_EQ(ws.send_buf.len, sizeof(expected));
    ASSERT_MEM_EQ(ws.send_buf.data, expected, sizeof(expected));

    ws_conn_free(&ws);
}

TEST(test_pong_data)
{
    ws_conn_t ws;
    const uint8_t expected[] = {0x8a, 0x03, 'f', 'o', 'o'};

    setup_accepted_connection(&ws);
    ASSERT_EQ(ws_pong(&ws, (const uint8_t *)"foo", 3), WS_OK);
    ASSERT_EQ(ws.send_buf.len, sizeof(expected));
    ASSERT_MEM_EQ(ws.send_buf.data, expected, sizeof(expected));

    ws_conn_free(&ws);
}

TEST(test_decode_hybi_text)
{
    uint8_t buf[] = {0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58};
    const uint8_t expected[] = {'H', 'e', 'l', 'l', 'o'};
    ws_frame_t frame;

    ASSERT_EQ(ws_decode_hybi(buf, sizeof(buf), &frame), (int)sizeof(buf));
    ASSERT_EQ(frame.fin, 1);
    ASSERT_EQ(frame.opcode, 0x1);
    ASSERT_TRUE(frame.masked);
    ASSERT_EQ(frame.length, sizeof(buf));
    ASSERT_EQ(frame.payload_len, sizeof(expected));
    ASSERT_MEM_EQ(frame.payload, expected, sizeof(expected));
}

TEST(test_decode_hybi_binary)
{
    uint8_t buf[] = {0x82, 0x04, 0x01, 0x02, 0x03, 0x04};
    const uint8_t expected[] = {0x01, 0x02, 0x03, 0x04};
    ws_frame_t frame;

    ASSERT_EQ(ws_decode_hybi(buf, sizeof(buf), &frame), (int)sizeof(buf));
    ASSERT_EQ(frame.fin, 1);
    ASSERT_EQ(frame.opcode, 0x2);
    ASSERT_EQ(frame.length, sizeof(buf));
    ASSERT_MEM_EQ(frame.payload, expected, sizeof(expected));
}

TEST(test_decode_hybi_extended_16bit_binary)
{
    uint8_t data[260];
    uint8_t buf[4 + 260];
    int i;
    ws_frame_t frame;

    for (i = 0; i < 65; i++) {
        data[i * 4 + 0] = 0x01;
        data[i * 4 + 1] = 0x02;
        data[i * 4 + 2] = 0x03;
        data[i * 4 + 3] = 0x04;
    }

    buf[0] = 0x82;
    buf[1] = 0x7e;
    buf[2] = 0x01;
    buf[3] = 0x04;
    memcpy(buf + 4, data, sizeof(data));

    ASSERT_EQ(ws_decode_hybi(buf, sizeof(buf), &frame), (int)sizeof(buf));
    ASSERT_EQ(frame.fin, 1);
    ASSERT_EQ(frame.opcode, 0x2);
    ASSERT_EQ(frame.length, sizeof(buf));
    ASSERT_EQ(frame.payload_len, sizeof(data));
    ASSERT_MEM_EQ(frame.payload, data, sizeof(data));
}

TEST(test_decode_hybi_extended_64bit_binary)
{
    uint8_t data[260];
    uint8_t buf[10 + 260];
    int i;
    ws_frame_t frame;

    for (i = 0; i < 65; i++) {
        data[i * 4 + 0] = 0x01;
        data[i * 4 + 1] = 0x02;
        data[i * 4 + 2] = 0x03;
        data[i * 4 + 3] = 0x04;
    }

    buf[0] = 0x82;
    buf[1] = 0x7f;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf[4] = 0x00;
    buf[5] = 0x00;
    buf[6] = 0x00;
    buf[7] = 0x00;
    buf[8] = 0x01;
    buf[9] = 0x04;
    memcpy(buf + 10, data, sizeof(data));

    ASSERT_EQ(ws_decode_hybi(buf, sizeof(buf), &frame), (int)sizeof(buf));
    ASSERT_EQ(frame.fin, 1);
    ASSERT_EQ(frame.opcode, 0x2);
    ASSERT_EQ(frame.length, sizeof(buf));
    ASSERT_EQ(frame.payload_len, sizeof(data));
    ASSERT_MEM_EQ(frame.payload, data, sizeof(data));
}

TEST(test_decode_hybi_multi)
{
    uint8_t buf1[] = {0x01, 0x03, 0x48, 0x65, 0x6c};
    uint8_t buf2[] = {0x80, 0x02, 0x6c, 0x6f};
    const uint8_t expected1[] = {'H', 'e', 'l'};
    const uint8_t expected2[] = {'l', 'o'};
    ws_frame_t frame1;
    ws_frame_t frame2;

    ASSERT_EQ(ws_decode_hybi(buf1, sizeof(buf1), &frame1), (int)sizeof(buf1));
    ASSERT_EQ(frame1.fin, 0);
    ASSERT_EQ(frame1.opcode, 0x1);
    ASSERT_EQ(frame1.length, sizeof(buf1));
    ASSERT_MEM_EQ(frame1.payload, expected1, sizeof(expected1));

    ASSERT_EQ(ws_decode_hybi(buf2, sizeof(buf2), &frame2), (int)sizeof(buf2));
    ASSERT_EQ(frame2.fin, 1);
    ASSERT_EQ(frame2.opcode, 0x0);
    ASSERT_EQ(frame2.length, sizeof(buf2));
    ASSERT_MEM_EQ(frame2.payload, expected2, sizeof(expected2));
}

TEST(test_encode_hybi_basic)
{
    ws_buf_t out;
    const uint8_t expected[] = {0x81, 0x05, 'H', 'e', 'l', 'l', 'o'};

    ws_buf_init(&out);
    ASSERT_EQ(ws_encode_hybi(0x1, (const uint8_t *)"Hello", 5, NULL, 1, &out), 0);
    ASSERT_EQ(out.len, sizeof(expected));
    ASSERT_MEM_EQ(out.data, expected, sizeof(expected));

    ws_buf_free(&out);
}

TEST_MAIN_BEGIN
    RUN_TEST(test_accept_success);
    RUN_TEST(test_accept_bad_version);
    RUN_TEST(test_accept_bad_upgrade);
    RUN_TEST(test_accept_missing_key);
    RUN_TEST(test_accept_protocol);
    RUN_TEST(test_accept_no_protocol);
    RUN_TEST(test_accept_missing_protocol_handler);
    RUN_TEST(test_accept_unsupported_protocol);
    RUN_TEST(test_ping);
    RUN_TEST(test_pong);
    RUN_TEST(test_ping_data);
    RUN_TEST(test_pong_data);
    RUN_TEST(test_decode_hybi_text);
    RUN_TEST(test_decode_hybi_binary);
    RUN_TEST(test_decode_hybi_extended_16bit_binary);
    RUN_TEST(test_decode_hybi_extended_64bit_binary);
    RUN_TEST(test_decode_hybi_multi);
    RUN_TEST(test_encode_hybi_basic);
TEST_MAIN_END
