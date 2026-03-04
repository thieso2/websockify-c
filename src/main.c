#include "websocket.h"
#include "http_parser.h"
#include "util.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define HANDSHAKE_MAX 65536
#define IO_BUF_SIZE 8192
#define MAX_CONNS 1024

typedef struct {
    int verbose;
    int traffic;
    char *record;
    int daemon;
    int run_once;
    int timeout;
    int idle_timeout;

    char *cert;
    char *key;
    char *key_password;
    int ssl_only;
    int ssl_target;
    int verify_client;
    char *cafile;
    char *ssl_version;
    char *ssl_ciphers;

    char *unix_listen;
    char *unix_listen_mode;
    char *unix_target;
    int inetd;
    char *web;
    int web_auth;
    char *wrap_mode;
    int source_is_ipv6;
    int libserver;

    char *target_cfg;
    char *token_plugin;
    char *token_source;
    int host_token;

    char *auth_plugin;
    char *auth_source;

    int heartbeat;
    char *log_file;
    char *syslog;
    int legacy_syslog;
    int file_only;

    int listen_fd;
    char *listen_host;
    int listen_port;
    char *target_host;
    int target_port;

    int has_wrap_cmd;
    int wrap_argc;
    char **wrap_argv;
} ws_options_t;

typedef struct {
    ws_buf_t raw;
    int consumed;
    char *method;
    char *path;
    char *version;
    ws_headers_t headers;
} http_request_t;

typedef enum {
    CONN_HTTP_RECV = 0,
    CONN_HTTP_SEND,
    CONN_WS,
    CONN_DEAD
} conn_state_t;

typedef struct {
    int used;
    conn_state_t state;
    int client_fd;
    int target_fd;
    int target_connecting;
    int target_open;
    int close_after_send;
    http_request_t req;
    int req_active;
    ws_conn_t ws;
    int ws_active;
    ws_buf_t out_http;
    ws_buf_t out_target;
} conn_t;

static volatile sig_atomic_t g_stop = 0;

typedef struct {
    unsigned long accepted;
    unsigned long closed;
    unsigned long http_requests;
    unsigned long ws_upgrades;
    unsigned long long client_in_bytes;
    unsigned long long client_out_bytes;
    unsigned long long target_in_bytes;
    unsigned long long target_out_bytes;
} stats_t;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "    %s [options] [source_addr:]source_port target_addr:target_port\n"
            "    %s [options] --token-plugin=CLASS [source_addr:]source_port\n"
            "    %s [options] --unix-target=FILE [source_addr:]source_port\n"
            "    %s [options] [source_addr:]source_port -- WRAP_COMMAND_LINE\n",
            prog, prog, prog, prog);
}

static void parser_error(const char *prog, const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    usage(prog);
}

static void init_options(ws_options_t *o)
{
    memset(o, 0, sizeof(*o));
    o->cert = "self.pem";
    o->ssl_version = "default";
    o->wrap_mode = "exit";
    o->listen_fd = -1;
}

static int parse_host_port(const char *arg, char **host_out, int *port_out)
{
    const char *colon = strrchr(arg, ':');
    char *host = NULL;
    char *endp = NULL;
    long p;

    if (colon) {
        size_t hlen = (size_t)(colon - arg);
        host = (char *)malloc(hlen + 1);
        if (!host) return -1;
        memcpy(host, arg, hlen);
        host[hlen] = '\0';
        if (hlen >= 2 && host[0] == '[' && host[hlen - 1] == ']') {
            memmove(host, host + 1, hlen - 2);
            host[hlen - 2] = '\0';
        }
        p = strtol(colon + 1, &endp, 10);
    } else {
        host = strdup("");
        if (!host) return -1;
        p = strtol(arg, &endp, 10);
    }

    if (!endp || *endp != '\0' || p < 1 || p > 65535) {
        free(host);
        return -1;
    }

    *host_out = host;
    *port_out = (int)p;
    return 0;
}

static int parse_target(const char *arg, char **host_out, int *port_out)
{
    const char *colon = strrchr(arg, ':');
    char *host;
    char *endp = NULL;
    long p;
    size_t hlen;

    if (!colon || colon == arg || *(colon + 1) == '\0') return -1;

    hlen = (size_t)(colon - arg);
    host = (char *)malloc(hlen + 1);
    if (!host) return -1;
    memcpy(host, arg, hlen);
    host[hlen] = '\0';
    if (hlen >= 2 && host[0] == '[' && host[hlen - 1] == ']') {
        memmove(host, host + 1, hlen - 2);
        host[hlen - 2] = '\0';
    }

    p = strtol(colon + 1, &endp, 10);
    if (!endp || *endp != '\0' || p < 1 || p > 65535) {
        free(host);
        return -1;
    }

    *host_out = host;
    *port_out = (int)p;
    return 0;
}

static int string_in(const char *v, const char *a, const char *b, const char *c, const char *d)
{
    return (strcmp(v, a) == 0) || (strcmp(v, b) == 0) || (strcmp(v, c) == 0) || (strcmp(v, d) == 0);
}

static int parse_options(int argc, char **argv, ws_options_t *o)
{
    int i;
    int dd = -1;
    int cargc;
    char **cargv;
    int opt;
    int idx = 0;
    int pos_count;
    char **pos_args;

    static struct option long_opts[] = {
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        {"traffic", no_argument, 0, 1001},
        {"record", required_argument, 0, 1002},
        {"daemon", no_argument, 0, 'D'},
        {"run-once", no_argument, 0, 1003},
        {"timeout", required_argument, 0, 1004},
        {"idle-timeout", required_argument, 0, 1005},
        {"cert", required_argument, 0, 1006},
        {"key", required_argument, 0, 1007},
        {"key-password", required_argument, 0, 1008},
        {"ssl-only", no_argument, 0, 1009},
        {"ssl-target", no_argument, 0, 1010},
        {"verify-client", no_argument, 0, 1011},
        {"cafile", required_argument, 0, 1012},
        {"ssl-version", required_argument, 0, 1013},
        {"ssl-ciphers", required_argument, 0, 1014},
        {"unix-listen", required_argument, 0, 1015},
        {"unix-listen-mode", required_argument, 0, 1016},
        {"unix-target", required_argument, 0, 1017},
        {"inetd", no_argument, 0, 1018},
        {"web", required_argument, 0, 1019},
        {"web-auth", no_argument, 0, 1020},
        {"wrap-mode", required_argument, 0, 1021},
        {"prefer-ipv6", no_argument, 0, '6'},
        {"libserver", no_argument, 0, 1022},
        {"target-config", required_argument, 0, 1023},
        {"token-plugin", required_argument, 0, 1024},
        {"token-source", required_argument, 0, 1025},
        {"host-token", no_argument, 0, 1026},
        {"auth-plugin", required_argument, 0, 1027},
        {"auth-source", required_argument, 0, 1028},
        {"heartbeat", required_argument, 0, 1029},
        {"log-file", required_argument, 0, 1030},
        {"syslog", required_argument, 0, 1031},
        {"legacy-syslog", no_argument, 0, 1032},
        {"file-only", no_argument, 0, 1033},
        {0, 0, 0, 0}
    };

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            dd = i;
            break;
        }
    }

    if (dd >= 0) {
        o->has_wrap_cmd = 1;
        o->wrap_argc = argc - dd - 1;
        o->wrap_argv = &argv[dd + 1];
        cargc = dd;
    } else {
        cargc = argc;
    }

    cargv = argv;
    opterr = 0;
    optind = 1;

    while ((opt = getopt_long(cargc, cargv, "hvD6", long_opts, &idx)) != -1) {
        switch (opt) {
        case 'h': usage(argv[0]); exit(0);
        case 'v': o->verbose = 1; break;
        case 'D': o->daemon = 1; break;
        case '6': o->source_is_ipv6 = 1; break;
        case 1001: o->traffic = 1; break;
        case 1002: o->record = optarg; break;
        case 1003: o->run_once = 1; break;
        case 1004: o->timeout = atoi(optarg); break;
        case 1005: o->idle_timeout = atoi(optarg); break;
        case 1006: o->cert = optarg; break;
        case 1007: o->key = optarg; break;
        case 1008: o->key_password = optarg; break;
        case 1009: o->ssl_only = 1; break;
        case 1010: o->ssl_target = 1; break;
        case 1011: o->verify_client = 1; break;
        case 1012: o->cafile = optarg; break;
        case 1013: o->ssl_version = optarg; break;
        case 1014: o->ssl_ciphers = optarg; break;
        case 1015: o->unix_listen = optarg; break;
        case 1016: o->unix_listen_mode = optarg; break;
        case 1017: o->unix_target = optarg; break;
        case 1018: o->inetd = 1; break;
        case 1019: o->web = optarg; break;
        case 1020: o->web_auth = 1; break;
        case 1021: o->wrap_mode = optarg; break;
        case 1022: o->libserver = 1; break;
        case 1023: o->target_cfg = optarg; break;
        case 1024: o->token_plugin = optarg; break;
        case 1025: o->token_source = optarg; break;
        case 1026: o->host_token = 1; break;
        case 1027: o->auth_plugin = optarg; break;
        case 1028: o->auth_source = optarg; break;
        case 1029: o->heartbeat = atoi(optarg); break;
        case 1030: o->log_file = optarg; break;
        case 1031: o->syslog = optarg; break;
        case 1032: o->legacy_syslog = 1; break;
        case 1033: o->file_only = 1; break;
        default: parser_error(argv[0], "error: invalid option"); return -1;
        }
    }

    if (!string_in(o->ssl_version, "default", "tlsv1_1", "tlsv1_2", "tlsv1_3")) {
        parser_error(argv[0], "error: invalid --ssl-version value");
        return -1;
    }
    if (!(strcmp(o->wrap_mode, "exit") == 0 || strcmp(o->wrap_mode, "ignore") == 0 || strcmp(o->wrap_mode, "respawn") == 0)) {
        parser_error(argv[0], "error: invalid --wrap-mode value");
        return -1;
    }

    if (o->token_source && !o->token_plugin) {
        parser_error(argv[0], "You must use --token-plugin to use --token-source");
        return -1;
    }
    if (o->host_token && !o->token_plugin) {
        parser_error(argv[0], "You must use --token-plugin to use --host-token");
        return -1;
    }
    if (o->auth_source && !o->auth_plugin) {
        parser_error(argv[0], "You must use --auth-plugin to use --auth-source");
        return -1;
    }
    if (o->web_auth && !o->auth_plugin) {
        parser_error(argv[0], "You must use --auth-plugin to use --web-auth");
        return -1;
    }
    if (o->web_auth && !o->web) {
        parser_error(argv[0], "You must use --web to use --web-auth");
        return -1;
    }
    if (o->legacy_syslog && !o->syslog) {
        parser_error(argv[0], "You must use --syslog to use --legacy-syslog");
        return -1;
    }

    if (o->target_cfg) {
        o->token_plugin = "TokenFile";
        o->token_source = o->target_cfg;
    }

    if (o->ssl_only) {
        struct stat st;
        if (stat(o->cert, &st) < 0) {
            char buf[512];
            snprintf(buf, sizeof(buf), "SSL only and %s not found", o->cert);
            parser_error(argv[0], buf);
            return -1;
        }
    }

    pos_count = cargc - optind;
    pos_args = &cargv[optind];

    if (o->inetd) {
        o->listen_fd = 0;
    } else if (o->unix_listen) {
        o->listen_fd = -1;
    } else {
        if (pos_count < 1) {
            parser_error(argv[0], "Too few arguments");
            return -1;
        }
        if (parse_host_port(pos_args[0], &o->listen_host, &o->listen_port) < 0) {
            parser_error(argv[0], "Error parsing listen port");
            return -1;
        }
        pos_args++;
        pos_count--;
    }

    if (o->has_wrap_cmd || o->unix_target || o->token_plugin) {
        o->target_host = NULL;
        o->target_port = 0;
    } else {
        if (pos_count < 1) {
            parser_error(argv[0], "Too few arguments");
            return -1;
        }
        if (parse_target(pos_args[0], &o->target_host, &o->target_port) < 0) {
            parser_error(argv[0], "Error parsing target");
            return -1;
        }
        pos_args++;
        pos_count--;
    }

    if (pos_count > 0 && !o->has_wrap_cmd) {
        parser_error(argv[0], "Too many arguments");
        return -1;
    }

    return 0;
}

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
    return 0;
}

static int send_buffer_nb_counted(int fd, ws_buf_t *buf, unsigned long long *counter)
{
    while (buf->len > 0) {
        ssize_t n = send(fd, buf->data, buf->len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
        if (n == 0) return -1;
        ws_buf_consume(buf, (size_t)n);
        *counter += (unsigned long long)n;
    }
    return 0;
}

static int create_listener(const char *host, int port, int prefer_ipv6)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *it;
    char port_s[16];
    int fd = -1;
    int one = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = prefer_ipv6 ? AF_INET6 : AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    snprintf(port_s, sizeof(port_s), "%d", port);
    if (getaddrinfo((host && host[0]) ? host : NULL, port_s, &hints, &res) != 0) return -1;

    for (it = res; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) continue;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(fd, it->ai_addr, it->ai_addrlen) == 0 && listen(fd, 128) == 0) break;
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    if (fd >= 0 && set_nonblocking(fd) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int connect_target_nb(const char *host, int port, int *connecting)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *it;
    char port_s[16];
    int fd = -1;

    *connecting = 0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_s, sizeof(port_s), "%d", port);

    if (getaddrinfo(host, port_s, &hints, &res) != 0) return -1;

    for (it = res; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) continue;
        if (set_nonblocking(fd) < 0) {
            close(fd);
            fd = -1;
            continue;
        }

        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) {
            *connecting = 0;
            break;
        }
        if (errno == EINPROGRESS) {
            *connecting = 1;
            break;
        }
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

static void http_request_init(http_request_t *r)
{
    memset(r, 0, sizeof(*r));
    ws_buf_init(&r->raw);
    ws_headers_init(&r->headers);
}

static void http_request_free(http_request_t *r)
{
    ws_buf_free(&r->raw);
    ws_headers_free(&r->headers);
    free(r->method);
    free(r->path);
    free(r->version);
}

static int path_has_parent_ref(const char *p)
{
    const char *s = p;
    while ((s = strstr(s, "..")) != NULL) {
        if ((s == p || s[-1] == '/') && (s[2] == '/' || s[2] == '\0')) return 1;
        s += 2;
    }
    return 0;
}

static int path_under_root(const char *root_real, const char *resolved)
{
    size_t root_len = strlen(root_real);
    if (strncmp(resolved, root_real, root_len) != 0) return 0;
    return resolved[root_len] == '\0' || resolved[root_len] == '/';
}

static void html_escape_append(ws_buf_t *out, const char *s)
{
    while (*s) {
        const char *rep = NULL;
        switch (*s) {
        case '&': rep = "&amp;"; break;
        case '<': rep = "&lt;"; break;
        case '>': rep = "&gt;"; break;
        case '"': rep = "&quot;"; break;
        case '\'': rep = "&#39;"; break;
        default: break;
        }
        if (rep) ws_buf_append(out, (const uint8_t *)rep, strlen(rep));
        else ws_buf_append(out, (const uint8_t *)s, 1);
        s++;
    }
}

static void url_escape_append(ws_buf_t *out, const char *s)
{
    while (*s) {
        unsigned char c = (unsigned char)*s;
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || c == '/') {
            ws_buf_append(out, (const uint8_t *)&c, 1);
        } else {
            char esc[4];
            snprintf(esc, sizeof(esc), "%%%02X", c);
            ws_buf_append(out, (const uint8_t *)esc, 3);
        }
        s++;
    }
}

static const char *guess_content_type(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    if (strcmp(dot, ".html") == 0 || strcmp(dot, ".htm") == 0) return "text/html";
    if (strcmp(dot, ".css") == 0) return "text/css";
    if (strcmp(dot, ".js") == 0) return "application/javascript";
    if (strcmp(dot, ".txt") == 0) return "text/plain";
    if (strcmp(dot, ".json") == 0) return "application/json";
    if (strcmp(dot, ".png") == 0) return "image/png";
    if (strcmp(dot, ".jpg") == 0 || strcmp(dot, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(dot, ".gif") == 0) return "image/gif";
    if (strcmp(dot, ".svg") == 0) return "image/svg+xml";
    return "application/octet-stream";
}

static int append_http_response(ws_buf_t *out, int code, const char *reason, const char *ctype, const uint8_t *body, size_t body_len, int head_only)
{
    char hdr[1024];
    int n = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 %d %s\r\n"
                     "Connection: close\r\n"
                     "Content-Type: %s\r\n"
                     "Content-Length: %zu\r\n"
                     "\r\n",
                     code, reason, ctype ? ctype : "text/plain", body_len);
    if (n <= 0 || (size_t)n >= sizeof(hdr)) return -1;
    if (ws_buf_append(out, (const uint8_t *)hdr, (size_t)n) < 0) return -1;
    if (!head_only && body && body_len > 0) {
        if (ws_buf_append(out, body, body_len) < 0) return -1;
    }
    return 0;
}

static int build_web_response(const ws_options_t *opt, const http_request_t *req, ws_buf_t *out)
{
    int head_only;
    char root_real[PATH_MAX];
    char rel[PATH_MAX];
    char candidate[PATH_MAX];
    char resolved[PATH_MAX];
    char *qmark;
    struct stat st;

    if (!opt->web) {
        const char *msg = "Method Not Allowed\n";
        return append_http_response(out, 405, "Method Not Allowed", "text/plain", (const uint8_t *)msg, strlen(msg), 0);
    }

    if (strcmp(req->method, "GET") != 0 && strcmp(req->method, "HEAD") != 0) {
        const char *msg = "Method Not Allowed\n";
        return append_http_response(out, 405, "Method Not Allowed", "text/plain", (const uint8_t *)msg, strlen(msg), 0);
    }
    head_only = (strcmp(req->method, "HEAD") == 0);

    if (!realpath(opt->web, root_real)) {
        const char *msg = "Web root not found\n";
        return append_http_response(out, 500, "Internal Server Error", "text/plain", (const uint8_t *)msg, strlen(msg), head_only);
    }

    snprintf(rel, sizeof(rel), "%s", req->path ? req->path : "/");
    qmark = strchr(rel, '?');
    if (qmark) *qmark = '\0';
    if (rel[0] == '\0') snprintf(rel, sizeof(rel), "/");
    if (rel[0] == '/') memmove(rel, rel + 1, strlen(rel));
    if (rel[0] == '\0') snprintf(rel, sizeof(rel), ".");
    if (path_has_parent_ref(rel)) {
        const char *msg = "Forbidden\n";
        return append_http_response(out, 403, "Forbidden", "text/plain", (const uint8_t *)msg, strlen(msg), head_only);
    }

    if (strlen(root_real) + 1 + strlen(rel) + 1 > sizeof(candidate)) {
        const char *msg = "Request URI Too Long\n";
        return append_http_response(out, 414, "Request-URI Too Long", "text/plain", (const uint8_t *)msg, strlen(msg), head_only);
    }
    {
        size_t root_len = strlen(root_real);
        size_t rel_len = strlen(rel);
        memcpy(candidate, root_real, root_len);
        candidate[root_len] = '/';
        memcpy(candidate + root_len + 1, rel, rel_len);
        candidate[root_len + 1 + rel_len] = '\0';
    }

    if (!realpath(candidate, resolved)) {
        const char *msg = "Not Found\n";
        return append_http_response(out, 404, "Not Found", "text/plain", (const uint8_t *)msg, strlen(msg), head_only);
    }
    if (!path_under_root(root_real, resolved)) {
        const char *msg = "Forbidden\n";
        return append_http_response(out, 403, "Forbidden", "text/plain", (const uint8_t *)msg, strlen(msg), head_only);
    }
    if (stat(resolved, &st) < 0) {
        const char *msg = "Not Found\n";
        return append_http_response(out, 404, "Not Found", "text/plain", (const uint8_t *)msg, strlen(msg), head_only);
    }

    if (S_ISDIR(st.st_mode)) {
        if (opt->file_only) {
            const char *msg = "Not Found\n";
            return append_http_response(out, 404, "Not Found", "text/plain", (const uint8_t *)msg, strlen(msg), head_only);
        }
        {
            DIR *d = opendir(resolved);
            struct dirent *ent;
            ws_buf_t body;
            if (!d) {
                const char *msg = "Forbidden\n";
                return append_http_response(out, 403, "Forbidden", "text/plain", (const uint8_t *)msg, strlen(msg), head_only);
            }
            ws_buf_init(&body);
            ws_buf_append(&body, (const uint8_t *)"<html><body><ul>\n", 17);
            while ((ent = readdir(d)) != NULL) {
                if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
                ws_buf_append(&body, (const uint8_t *)"<li><a href=\"", 13);
                url_escape_append(&body, ent->d_name);
                ws_buf_append(&body, (const uint8_t *)"\">", 2);
                html_escape_append(&body, ent->d_name);
                ws_buf_append(&body, (const uint8_t *)"</a></li>\n", 10);
            }
            ws_buf_append(&body, (const uint8_t *)"</ul></body></html>\n", 19);
            closedir(d);
            if (append_http_response(out, 200, "OK", "text/html", body.data, body.len, head_only) < 0) {
                ws_buf_free(&body);
                return -1;
            }
            ws_buf_free(&body);
            return 0;
        }
    }

    if (S_ISREG(st.st_mode)) {
        FILE *f = fopen(resolved, "rb");
        ws_buf_t body;
        uint8_t tmp[IO_BUF_SIZE];
        size_t rn;
        if (!f) {
            const char *msg = "Not Found\n";
            return append_http_response(out, 404, "Not Found", "text/plain", (const uint8_t *)msg, strlen(msg), head_only);
        }
        ws_buf_init(&body);
        while ((rn = fread(tmp, 1, sizeof(tmp), f)) > 0) {
            if (ws_buf_append(&body, tmp, rn) < 0) {
                fclose(f);
                ws_buf_free(&body);
                return -1;
            }
        }
        fclose(f);
        if (append_http_response(out, 200, "OK", guess_content_type(resolved), body.data, body.len, head_only) < 0) {
            ws_buf_free(&body);
            return -1;
        }
        ws_buf_free(&body);
        return 0;
    }

    {
        const char *msg = "Not Found\n";
        return append_http_response(out, 404, "Not Found", "text/plain", (const uint8_t *)msg, strlen(msg), head_only);
    }
}

static int is_websocket_upgrade(const http_request_t *req)
{
    const char *upgrade = ws_headers_get(&req->headers, "Upgrade");
    return (upgrade && strcasecmp(upgrade, "websocket") == 0);
}

static void conn_reset(conn_t *c)
{
    memset(c, 0, sizeof(*c));
    c->client_fd = -1;
    c->target_fd = -1;
}

static void conn_init(conn_t *c, int client_fd)
{
    conn_reset(c);
    c->used = 1;
    c->state = CONN_HTTP_RECV;
    c->client_fd = client_fd;
    c->target_fd = -1;
    c->req_active = 1;
    http_request_init(&c->req);
    ws_buf_init(&c->out_http);
    ws_buf_init(&c->out_target);
}

static void conn_close(conn_t *c)
{
    if (c->client_fd >= 0) close(c->client_fd);
    if (c->target_fd >= 0) close(c->target_fd);
    if (c->req_active) http_request_free(&c->req);
    if (c->ws_active) ws_conn_free(&c->ws);
    ws_buf_free(&c->out_http);
    ws_buf_free(&c->out_target);
    conn_reset(c);
}

static int find_free_conn(conn_t *conns)
{
    int i;
    for (i = 0; i < MAX_CONNS; i++) if (!conns[i].used) return i;
    return -1;
}

static void process_http_if_complete(conn_t *c, const ws_options_t *opt)
{
    int consumed;

    if (!c->req_active || c->state != CONN_HTTP_RECV) return;

    consumed = ws_http_parse_request(c->req.raw.data, c->req.raw.len,
                                     &c->req.method, &c->req.path, &c->req.version,
                                     &c->req.headers);
    if (consumed < 0) {
        c->state = CONN_DEAD;
        return;
    }
    if (consumed == 0) return;

    c->req.consumed = consumed;

    if (is_websocket_upgrade(&c->req)) {
        int connecting = 0;
        if (!c->req.method || strcmp(c->req.method, "GET") != 0) {
            const char *msg = "Method Not Allowed\n";
            append_http_response(&c->out_http, 405, "Method Not Allowed", "text/plain", (const uint8_t *)msg, strlen(msg), 0);
            c->state = CONN_HTTP_SEND;
            c->close_after_send = 1;
            return;
        }

        ws_conn_init(&c->ws, 0);
        c->ws_active = 1;
        c->ws.ctx.io_send = NULL;
        c->ws.ctx.user_data = NULL;
        if (ws_accept(&c->ws, &c->req.headers) != WS_OK) {
            const char *msg = "Bad Request\n";
            append_http_response(&c->out_http, 400, "Bad Request", "text/plain", (const uint8_t *)msg, strlen(msg), 0);
            c->state = CONN_HTTP_SEND;
            c->close_after_send = 1;
            return;
        }

        if ((size_t)c->req.consumed < c->req.raw.len) {
            ws_buf_append(&c->ws.recv_buf, c->req.raw.data + c->req.consumed, c->req.raw.len - (size_t)c->req.consumed);
        }

        http_request_free(&c->req);
        c->req_active = 0;

        c->target_fd = connect_target_nb(opt->target_host, opt->target_port, &connecting);
        if (c->target_fd < 0) {
            ws_shutdown(&c->ws, 1011, "Failed to connect to downstream server");
            c->close_after_send = 1;
            c->state = CONN_WS;
            return;
        }
        c->target_connecting = connecting;
        c->target_open = connecting ? 0 : 1;
        c->state = CONN_WS;
        return;
    }

    if (build_web_response(opt, &c->req, &c->out_http) < 0) {
        c->state = CONN_DEAD;
        return;
    }
    c->state = CONN_HTTP_SEND;
    c->close_after_send = 1;
}

static int count_active_conns(conn_t *conns)
{
    int i;
    int n = 0;
    for (i = 0; i < MAX_CONNS; i++) if (conns[i].used) n++;
    return n;
}

static int count_ws_conns(conn_t *conns)
{
    int i;
    int n = 0;
    for (i = 0; i < MAX_CONNS; i++) {
        if (conns[i].used && conns[i].state == CONN_WS) n++;
    }
    return n;
}

static void maybe_log_stats(const ws_options_t *opt, conn_t *conns, stats_t *stats, time_t *last_log)
{
    time_t now;
    if (!opt->verbose) return;
    now = time(NULL);
    if (*last_log == 0) {
        *last_log = now;
        return;
    }
    if (now - *last_log < 5) return;
    *last_log = now;
    fprintf(stderr,
            "[stats] active=%d ws=%d accepted=%lu closed=%lu http=%lu upgrades=%lu "
            "c_in=%llu c_out=%llu t_in=%llu t_out=%llu\n",
            count_active_conns(conns),
            count_ws_conns(conns),
            stats->accepted,
            stats->closed,
            stats->http_requests,
            stats->ws_upgrades,
            stats->client_in_bytes,
            stats->client_out_bytes,
            stats->target_in_bytes,
            stats->target_out_bytes);
}

static void pump_ws_frames(conn_t *c)
{
    ws_frame_t frame;

    while (ws_decode_hybi(c->ws.recv_buf.data, c->ws.recv_buf.len, &frame) > 0) {
        int consumed = (int)frame.length;
        if (frame.opcode == WS_OPCODE_CLOSE) {
            ws_shutdown(&c->ws, 1000, "");
            c->close_after_send = 1;
            c->target_open = 0;
            if (c->target_fd >= 0) {
                close(c->target_fd);
                c->target_fd = -1;
            }
        } else if (frame.opcode == WS_OPCODE_PING) {
            ws_pong(&c->ws, frame.payload, frame.payload_len);
        } else if (frame.opcode == WS_OPCODE_TEXT || frame.opcode == WS_OPCODE_BINARY || frame.opcode == WS_OPCODE_CONTINUATION) {
            ws_buf_append(&c->out_target, frame.payload, frame.payload_len);
        }
        ws_buf_consume(&c->ws.recv_buf, (size_t)consumed);
    }
}

int main(int argc, char **argv)
{
    ws_options_t opt;
    conn_t conns[MAX_CONNS];
    stats_t stats;
    int listen_fd;
    int i;
    int warned = 0;
    time_t last_stats_log = 0;

    init_options(&opt);
    if (parse_options(argc, argv, &opt) < 0) return 2;

    if (opt.ssl_only || opt.ssl_target || opt.verify_client || opt.cafile || opt.key || opt.key_password || opt.ssl_ciphers) {
        fprintf(stderr, "error: TLS options are parsed but not implemented in native C runtime yet\n");
        return 2;
    }
    if (opt.unix_listen || opt.unix_target || opt.inetd || opt.has_wrap_cmd) {
        fprintf(stderr, "error: unix/inetd/wrap modes are parsed but not implemented in native C runtime yet\n");
        return 2;
    }
    if (opt.web_auth) {
        fprintf(stderr, "error: --web-auth is parsed but not implemented in native C runtime yet\n");
        return 2;
    }
    if (opt.token_plugin || opt.auth_plugin || opt.host_token || opt.target_cfg) {
        fprintf(stderr, "error: token/auth plugins are parsed but not implemented in native C runtime yet\n");
        return 2;
    }
    if (opt.libserver || opt.syslog || opt.legacy_syslog || opt.log_file || opt.daemon || opt.record || opt.traffic || opt.timeout || opt.idle_timeout) {
        fprintf(stderr, "warning: some options are currently ignored in native C runtime\n");
        warned = 1;
    }

    listen_fd = create_listener(opt.listen_host, opt.listen_port, opt.source_is_ipv6);
    if (listen_fd < 0) {
        perror("listen");
        free(opt.listen_host);
        free(opt.target_host);
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    for (i = 0; i < MAX_CONNS; i++) conn_reset(&conns[i]);
    memset(&stats, 0, sizeof(stats));

    fprintf(stderr, "websockify-codex listening on %s:%d -> %s:%d\n",
            (opt.listen_host && opt.listen_host[0]) ? opt.listen_host : "0.0.0.0",
            opt.listen_port,
            opt.target_host,
            opt.target_port);
    if (warned) fprintf(stderr, "warning: runtime behavior differs from Python for ignored options\n");

    while (!g_stop) {
        fd_set rfds, wfds;
        int maxfd = listen_fd;
        struct timeval tv;
        struct timeval *tvp = NULL;

        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_SET(listen_fd, &rfds);

        for (i = 0; i < MAX_CONNS; i++) {
            conn_t *c = &conns[i];
            if (!c->used) continue;

            if (c->state == CONN_HTTP_RECV) {
                FD_SET(c->client_fd, &rfds);
                if (c->client_fd > maxfd) maxfd = c->client_fd;
            } else if (c->state == CONN_HTTP_SEND) {
                if (c->out_http.len > 0) {
                    FD_SET(c->client_fd, &wfds);
                    if (c->client_fd > maxfd) maxfd = c->client_fd;
                }
            } else if (c->state == CONN_WS) {
                FD_SET(c->client_fd, &rfds);
                if (c->client_fd > maxfd) maxfd = c->client_fd;

                if (c->ws.send_buf.len > 0) {
                    FD_SET(c->client_fd, &wfds);
                    if (c->client_fd > maxfd) maxfd = c->client_fd;
                }

                if (c->target_fd >= 0) {
                    if (c->target_connecting || c->out_target.len > 0) {
                        FD_SET(c->target_fd, &wfds);
                        if (c->target_fd > maxfd) maxfd = c->target_fd;
                    }
                    if (c->target_open) {
                        FD_SET(c->target_fd, &rfds);
                        if (c->target_fd > maxfd) maxfd = c->target_fd;
                    }
                }
            }
        }

        if (opt.verbose) {
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            tvp = &tv;
        }

        if (select(maxfd + 1, &rfds, &wfds, NULL, tvp) < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

        if (FD_ISSET(listen_fd, &rfds)) {
            while (1) {
                int cfd = accept(listen_fd, NULL, NULL);
                int idx;
                if (cfd < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
                    perror("accept");
                    break;
                }
                if (set_nonblocking(cfd) < 0) {
                    close(cfd);
                    continue;
                }
                idx = find_free_conn(conns);
                if (idx < 0) {
                    close(cfd);
                    continue;
                }
                conn_init(&conns[idx], cfd);
                stats.accepted++;
            }
        }

        for (i = 0; i < MAX_CONNS; i++) {
            conn_t *c = &conns[i];
            if (!c->used) continue;

            if (c->state == CONN_HTTP_RECV && FD_ISSET(c->client_fd, &rfds)) {
                uint8_t tmp[IO_BUF_SIZE];
                ssize_t n = recv(c->client_fd, tmp, sizeof(tmp), 0);
                if (n <= 0) {
                    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                    } else {
                        c->state = CONN_DEAD;
                    }
                } else {
                    stats.client_in_bytes += (unsigned long long)n;
                    if (ws_buf_append(&c->req.raw, tmp, (size_t)n) < 0) c->state = CONN_DEAD;
                    else {
                        int prev_state = c->state;
                        process_http_if_complete(c, &opt);
                        if (prev_state == CONN_HTTP_RECV && c->state != CONN_HTTP_RECV) {
                            stats.http_requests++;
                            if (c->state == CONN_WS) stats.ws_upgrades++;
                        }
                    }
                }
            }

            if (c->state == CONN_HTTP_SEND && c->out_http.len > 0 && FD_ISSET(c->client_fd, &wfds)) {
                if (send_buffer_nb_counted(c->client_fd, &c->out_http, &stats.client_out_bytes) < 0) c->state = CONN_DEAD;
            }
            if (c->state == CONN_HTTP_SEND && c->out_http.len == 0 && c->close_after_send) {
                c->state = CONN_DEAD;
            }

            if (c->state == CONN_WS) {
                if (FD_ISSET(c->client_fd, &rfds)) {
                    uint8_t tmp[IO_BUF_SIZE];
                    ssize_t n = recv(c->client_fd, tmp, sizeof(tmp), 0);
                    if (n == 0) {
                        c->state = CONN_DEAD;
                    } else if (n < 0) {
                        if (!(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) c->state = CONN_DEAD;
                    } else {
                        stats.client_in_bytes += (unsigned long long)n;
                        if (ws_buf_append(&c->ws.recv_buf, tmp, (size_t)n) < 0) c->state = CONN_DEAD;
                        else pump_ws_frames(c);
                    }
                }

                if (c->target_fd >= 0 && c->target_connecting && FD_ISSET(c->target_fd, &wfds)) {
                    int err = 0;
                    socklen_t sl = sizeof(err);
                    if (getsockopt(c->target_fd, SOL_SOCKET, SO_ERROR, &err, &sl) < 0 || err != 0) {
                        ws_shutdown(&c->ws, 1011, "Failed to connect to downstream server");
                        close(c->target_fd);
                        c->target_fd = -1;
                        c->target_connecting = 0;
                        c->target_open = 0;
                        c->close_after_send = 1;
                    } else {
                        c->target_connecting = 0;
                        c->target_open = 1;
                    }
                }

                if (c->target_fd >= 0 && c->target_open && FD_ISSET(c->target_fd, &rfds)) {
                    uint8_t tmp[IO_BUF_SIZE];
                    ssize_t n = recv(c->target_fd, tmp, sizeof(tmp), 0);
                    if (n == 0) {
                        close(c->target_fd);
                        c->target_fd = -1;
                        c->target_open = 0;
                        ws_shutdown(&c->ws, 1000, "Target closed");
                        c->close_after_send = 1;
                    } else if (n < 0) {
                        if (!(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) c->state = CONN_DEAD;
                    } else {
                        stats.target_in_bytes += (unsigned long long)n;
                        if (ws_send(&c->ws, tmp, (size_t)n) != WS_OK) c->state = CONN_DEAD;
                    }
                }

                if (c->target_fd >= 0 && c->out_target.len > 0 && FD_ISSET(c->target_fd, &wfds) && !c->target_connecting) {
                    if (send_buffer_nb_counted(c->target_fd, &c->out_target, &stats.target_out_bytes) < 0) c->state = CONN_DEAD;
                }

                if (c->ws.send_buf.len > 0 && FD_ISSET(c->client_fd, &wfds)) {
                    if (send_buffer_nb_counted(c->client_fd, &c->ws.send_buf, &stats.client_out_bytes) < 0) c->state = CONN_DEAD;
                }

                if (c->close_after_send && c->ws.send_buf.len == 0 && c->out_target.len == 0) c->state = CONN_DEAD;
            }

            if (c->state == CONN_DEAD) {
                conn_close(c);
                stats.closed++;
                if (opt.run_once) {
                    g_stop = 1;
                }
            }
        }

        maybe_log_stats(&opt, conns, &stats, &last_stats_log);
    }

    for (i = 0; i < MAX_CONNS; i++) if (conns[i].used) conn_close(&conns[i]);
    close(listen_fd);
    free(opt.listen_host);
    free(opt.target_host);
    return 0;
}
