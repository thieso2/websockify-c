#include "base64.h"
#include <string.h>

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const uint8_t b64_inv[256] = {
    ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
    ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
    ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
    ['Y']=24,['Z']=25,
    ['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,['g']=32,['h']=33,
    ['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,['o']=40,['p']=41,
    ['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,['w']=48,['x']=49,
    ['y']=50,['z']=51,
    ['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,['6']=58,['7']=59,
    ['8']=60,['9']=61,['+']=62,['/']=63,
};

static int b64_valid(uint8_t c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

int ws_base64_encode(char *out, size_t out_cap, const uint8_t *in, size_t len)
{
    size_t needed = ((len + 2) / 3) * 4 + 1;
    if (out_cap < needed)
        return -1;

    size_t i, j;
    for (i = 0, j = 0; i + 2 < len; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
        out[j++] = b64_table[(v >> 18) & 0x3F];
        out[j++] = b64_table[(v >> 12) & 0x3F];
        out[j++] = b64_table[(v >>  6) & 0x3F];
        out[j++] = b64_table[v & 0x3F];
    }
    if (i < len) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < len)
            v |= (uint32_t)in[i+1] << 8;
        out[j++] = b64_table[(v >> 18) & 0x3F];
        out[j++] = b64_table[(v >> 12) & 0x3F];
        out[j++] = (i + 1 < len) ? b64_table[(v >> 6) & 0x3F] : '=';
        out[j++] = '=';
    }
    out[j] = '\0';
    return (int)j;
}

int ws_base64_decode(uint8_t *out, size_t out_cap, const char *in, size_t len)
{
    /* skip trailing whitespace */
    while (len > 0 && (in[len-1] == '\n' || in[len-1] == '\r' || in[len-1] == ' '))
        len--;

    if (len == 0) {
        return 0;
    }

    /* must be multiple of 4 */
    if (len % 4 != 0)
        return -1;

    size_t pad = 0;
    if (in[len-1] == '=') pad++;
    if (len >= 2 && in[len-2] == '=') pad++;

    size_t out_len = (len / 4) * 3 - pad;
    if (out_cap < out_len)
        return -1;

    size_t i, j;
    for (i = 0, j = 0; i < len; i += 4) {
        if (!b64_valid(in[i]) || !b64_valid(in[i+1]) ||
            !b64_valid(in[i+2]) || !b64_valid(in[i+3]))
            return -1;

        uint32_t a = b64_inv[(uint8_t)in[i]];
        uint32_t b = b64_inv[(uint8_t)in[i+1]];
        uint32_t c = b64_inv[(uint8_t)in[i+2]];
        uint32_t d = b64_inv[(uint8_t)in[i+3]];
        uint32_t v = (a << 18) | (b << 12) | (c << 6) | d;

        if (j < out_len) out[j++] = (v >> 16) & 0xFF;
        if (j < out_len) out[j++] = (v >>  8) & 0xFF;
        if (j < out_len) out[j++] = v & 0xFF;
    }
    return (int)out_len;
}
