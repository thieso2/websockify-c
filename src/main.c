#include "websocket.h"
#include "http_parser.h"
#include "util.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <strings.h>
#include <unistd.h>

#define HANDSHAKE_MAX 65536
#define IO_BUF_SIZE 8192

static volatile sig_atomic_t g_stop = 0;

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
    int fd;
} ws_fd_ctx_t;

typedef struct {
    ws_buf_t raw;
    int consumed;
    char *method;
    char *path;
    char *version;
    ws_headers_t headers;
} http_request_t;

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
    o->timeout = 0;
    o->idle_timeout = 0;
    o->cert = "self.pem";
    o->ssl_version = "default";
    o->wrap_mode = "exit";
    o->heartbeat = 0;
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
        if (!host) {
            return -1;
        }
        memcpy(host, arg, hlen);
        host[hlen] = '\0';
        if (hlen >= 2 && host[0] == '[' && host[hlen - 1] == ']') {
            memmove(host, host + 1, hlen - 2);
            host[hlen - 2] = '\0';
        }
        p = strtol(colon + 1, &endp, 10);
    } else {
        host = strdup("");
        if (!host) {
            return -1;
        }
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

    if (!colon || colon == arg || *(colon + 1) == '\0') {
        return -1;
    }

    hlen = (size_t)(colon - arg);
    host = (char *)malloc(hlen + 1);
    if (!host) {
        return -1;
    }
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
        o->has_wrap_cmd = 0;
        o->wrap_argc = 0;
        o->wrap_argv = NULL;
        cargc = argc;
    }

    cargv = argv;

    opterr = 0;
    optind = 1;
    while ((opt = getopt_long(cargc, cargv, "hvD6", long_opts, &idx)) != -1) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            exit(0);
        case 'v':
            o->verbose = 1;
            break;
        case 'D':
            o->daemon = 1;
            break;
        case '6':
            o->source_is_ipv6 = 1;
            break;
        case 1001:
            o->traffic = 1;
            break;
        case 1002:
            o->record = optarg;
            break;
        case 1003:
            o->run_once = 1;
            break;
        case 1004:
            o->timeout = atoi(optarg);
            break;
        case 1005:
            o->idle_timeout = atoi(optarg);
            break;
        case 1006:
            o->cert = optarg;
            break;
        case 1007:
            o->key = optarg;
            break;
        case 1008:
            o->key_password = optarg;
            break;
        case 1009:
            o->ssl_only = 1;
            break;
        case 1010:
            o->ssl_target = 1;
            break;
        case 1011:
            o->verify_client = 1;
            break;
        case 1012:
            o->cafile = optarg;
            break;
        case 1013:
            o->ssl_version = optarg;
            break;
        case 1014:
            o->ssl_ciphers = optarg;
            break;
        case 1015:
            o->unix_listen = optarg;
            break;
        case 1016:
            o->unix_listen_mode = optarg;
            break;
        case 1017:
            o->unix_target = optarg;
            break;
        case 1018:
            o->inetd = 1;
            break;
        case 1019:
            o->web = optarg;
            break;
        case 1020:
            o->web_auth = 1;
            break;
        case 1021:
            o->wrap_mode = optarg;
            break;
        case 1022:
            o->libserver = 1;
            break;
        case 1023:
            o->target_cfg = optarg;
            break;
        case 1024:
            o->token_plugin = optarg;
            break;
        case 1025:
            o->token_source = optarg;
            break;
        case 1026:
            o->host_token = 1;
            break;
        case 1027:
            o->auth_plugin = optarg;
            break;
        case 1028:
            o->auth_source = optarg;
            break;
        case 1029:
            o->heartbeat = atoi(optarg);
            break;
        case 1030:
            o->log_file = optarg;
            break;
        case 1031:
            o->syslog = optarg;
            break;
        case 1032:
            o->legacy_syslog = 1;
            break;
        case 1033:
            o->file_only = 1;
            break;
        default:
            parser_error(argv[0], "error: invalid option");
            return -1;
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

static ssize_t ws_fd_send(ws_ctx_t *ctx, const uint8_t *data, size_t len)
{
    ws_fd_ctx_t *fd_ctx = (ws_fd_ctx_t *)ctx->user_data;
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd_ctx->fd, data + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            break;
        }
        off += (size_t)n;
    }
    return (ssize_t)off;
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

    if (getaddrinfo((host && host[0]) ? host : NULL, port_s, &hints, &res) != 0) {
        return -1;
    }

    for (it = res; it != NULL; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) {
            continue;
        }
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(fd, it->ai_addr, it->ai_addrlen) == 0 && listen(fd, 64) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

static int connect_target(const char *host, int port)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *it;
    char port_s[16];
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_s, sizeof(port_s), "%d", port);

    if (getaddrinfo(host, port_s, &hints, &res) != 0) {
        return -1;
    }

    for (it = res; it != NULL; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) {
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

static int read_http_request(int client_fd, http_request_t *req)
{
    uint8_t tmp[IO_BUF_SIZE];
    int consumed;

    while (req->raw.len < HANDSHAKE_MAX) {
        ssize_t n = recv(client_fd, tmp, sizeof(tmp), 0);
        if (n <= 0) {
            return -1;
        }
        if (ws_buf_append(&req->raw, tmp, (size_t)n) < 0) {
            return -1;
        }

        consumed = ws_http_parse_request(req->raw.data, req->raw.len, &req->method, &req->path, &req->version, &req->headers);
        if (consumed < 0) {
            return -1;
        }
        if (consumed > 0) {
            req->consumed = consumed;
            return 0;
        }
    }
    return -1;
}

static int send_http_response(int fd, int code, const char *reason, const char *ctype, const uint8_t *body, size_t body_len, int head_only)
{
    char hdr[1024];
    int n = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 %d %s\r\n"
                     "Connection: close\r\n"
                     "Content-Type: %s\r\n"
                     "Content-Length: %zu\r\n"
                     "\r\n",
                     code, reason, ctype ? ctype : "text/plain", body_len);
    if (n <= 0 || (size_t)n >= sizeof(hdr)) {
        return -1;
    }
    if (send(fd, hdr, (size_t)n, 0) < 0) {
        return -1;
    }
    if (!head_only && body_len > 0) {
        size_t off = 0;
        while (off < body_len) {
            ssize_t wn = send(fd, body + off, body_len - off, 0);
            if (wn < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -1;
            }
            off += (size_t)wn;
        }
    }
    return 0;
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

static int path_has_parent_ref(const char *p)
{
    const char *s = p;
    while ((s = strstr(s, "..")) != NULL) {
        if ((s == p || s[-1] == '/') && (s[2] == '/' || s[2] == '\0')) {
            return 1;
        }
        s += 2;
    }
    return 0;
}

static int serve_web_request(int client_fd, const ws_options_t *opt, const http_request_t *req)
{
    int head_only;
    char root_real[PATH_MAX];
    char rel[PATH_MAX];
    char candidate[PATH_MAX];
    char resolved[PATH_MAX];
    struct stat st;
    char *qmark;

    if (!opt->web) {
        const char *msg = "Method Not Allowed\n";
        return send_http_response(client_fd, 405, "Method Not Allowed", "text/plain", (const uint8_t *)msg, strlen(msg), 0);
    }

    if (strcmp(req->method, "GET") != 0 && strcmp(req->method, "HEAD") != 0) {
        const char *msg = "Method Not Allowed\n";
        return send_http_response(client_fd, 405, "Method Not Allowed", "text/plain", (const uint8_t *)msg, strlen(msg), 0);
    }
    head_only = (strcmp(req->method, "HEAD") == 0);

    if (!realpath(opt->web, root_real)) {
        const char *msg = "Web root not found\n";
        return send_http_response(client_fd, 500, "Internal Server Error", "text/plain", (const uint8_t *)msg, strlen(msg), head_only);
    }

    snprintf(rel, sizeof(rel), "%s", req->path ? req->path : "/");
    qmark = strchr(rel, '?');
    if (qmark) {
        *qmark = '\0';
    }
    if (rel[0] == '\0') {
        snprintf(rel, sizeof(rel), "/");
    }
    if (rel[0] == '/') {
        memmove(rel, rel + 1, strlen(rel));
    }
    if (rel[0] == '\0') {
        snprintf(rel, sizeof(rel), ".");
    }
    if (path_has_parent_ref(rel)) {
        const char *msg = "Forbidden\n";
        return send_http_response(client_fd, 403, "Forbidden", "text/plain", (const uint8_t *)msg, strlen(msg), head_only);
    }

    snprintf(candidate, sizeof(candidate), "%s/%s", root_real, rel);
    if (!realpath(candidate, resolved)) {
        const char *msg = "Not Found\n";
        return send_http_response(client_fd, 404, "Not Found", "text/plain", (const uint8_t *)msg, strlen(msg), head_only);
    }
    if (strncmp(resolved, root_real, strlen(root_real)) != 0) {
        const char *msg = "Forbidden\n";
        return send_http_response(client_fd, 403, "Forbidden", "text/plain", (const uint8_t *)msg, strlen(msg), head_only);
    }
    if (stat(resolved, &st) < 0) {
        const char *msg = "Not Found\n";
        return send_http_response(client_fd, 404, "Not Found", "text/plain", (const uint8_t *)msg, strlen(msg), head_only);
    }

    if (S_ISDIR(st.st_mode)) {
        if (opt->file_only) {
            const char *msg = "Not Found\n";
            return send_http_response(client_fd, 404, "Not Found", "text/plain", (const uint8_t *)msg, strlen(msg), head_only);
        } else {
            DIR *d = opendir(resolved);
            ws_buf_t body;
            struct dirent *ent;
            if (!d) {
                const char *msg = "Forbidden\n";
                return send_http_response(client_fd, 403, "Forbidden", "text/plain", (const uint8_t *)msg, strlen(msg), head_only);
            }
            ws_buf_init(&body);
            ws_buf_append(&body, (const uint8_t *)"<html><body><ul>\n", 17);
            while ((ent = readdir(d)) != NULL) {
                char line[512];
                if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
                    continue;
                }
                snprintf(line, sizeof(line), "<li><a href=\"%s\">%s</a></li>\n", ent->d_name, ent->d_name);
                ws_buf_append(&body, (const uint8_t *)line, strlen(line));
            }
            ws_buf_append(&body, (const uint8_t *)"</ul></body></html>\n", 19);
            closedir(d);
            send_http_response(client_fd, 200, "OK", "text/html", body.data, body.len, head_only);
            ws_buf_free(&body);
            return 0;
        }
    }

    if (S_ISREG(st.st_mode)) {
        FILE *f = fopen(resolved, "rb");
        ws_buf_t body;
        uint8_t tmp[IO_BUF_SIZE];
        size_t rn;
        int rc;
        if (!f) {
            const char *msg = "Not Found\n";
            return send_http_response(client_fd, 404, "Not Found", "text/plain", (const uint8_t *)msg, strlen(msg), head_only);
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
        rc = send_http_response(client_fd, 200, "OK", guess_content_type(resolved), body.data, body.len, head_only);
        ws_buf_free(&body);
        return rc;
    }

    {
        const char *msg = "Not Found\n";
        return send_http_response(client_fd, 404, "Not Found", "text/plain", (const uint8_t *)msg, strlen(msg), head_only);
    }
}

static int proxy_connection(int client_fd, int target_fd, ws_conn_t *ws, ws_buf_t *prefetched)
{
    uint8_t io_buf[IO_BUF_SIZE];

    if (prefetched->len > 0 && ws_buf_append(&ws->recv_buf, prefetched->data, prefetched->len) < 0) {
        return -1;
    }

    while (!g_stop) {
        fd_set rfds;
        int maxfd;
        int rc;
        ws_frame_t frame;

        while (ws_decode_hybi(ws->recv_buf.data, ws->recv_buf.len, &frame) > 0) {
            int consumed = (int)frame.length;
            if (frame.opcode == WS_OPCODE_CLOSE) {
                ws_shutdown(ws, 1000, "");
                return 0;
            }
            if (frame.opcode == WS_OPCODE_PING) {
                if (ws_pong(ws, frame.payload, frame.payload_len) != WS_OK) {
                    return -1;
                }
            } else if (frame.opcode == WS_OPCODE_TEXT ||
                       frame.opcode == WS_OPCODE_BINARY ||
                       frame.opcode == WS_OPCODE_CONTINUATION) {
                size_t off = 0;
                while (off < frame.payload_len) {
                    ssize_t wn = send(target_fd, frame.payload + off, frame.payload_len - off, 0);
                    if (wn < 0) {
                        if (errno == EINTR) {
                            continue;
                        }
                        return -1;
                    }
                    if (wn == 0) {
                        return 0;
                    }
                    off += (size_t)wn;
                }
            }

            ws_buf_consume(&ws->recv_buf, (size_t)consumed);
        }

        FD_ZERO(&rfds);
        FD_SET(client_fd, &rfds);
        FD_SET(target_fd, &rfds);
        maxfd = client_fd > target_fd ? client_fd : target_fd;

        rc = select(maxfd + 1, &rfds, NULL, NULL, NULL);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (FD_ISSET(client_fd, &rfds)) {
            ssize_t n = recv(client_fd, io_buf, sizeof(io_buf), 0);
            if (n <= 0) {
                return 0;
            }
            if (ws_buf_append(&ws->recv_buf, io_buf, (size_t)n) < 0) {
                return -1;
            }
        }

        if (FD_ISSET(target_fd, &rfds)) {
            ssize_t n = recv(target_fd, io_buf, sizeof(io_buf), 0);
            if (n <= 0) {
                return 0;
            }
            if (ws_send(ws, io_buf, (size_t)n) != WS_OK) {
                return -1;
            }
        }
    }

    return 0;
}

static int is_websocket_upgrade(const http_request_t *req)
{
    const char *upgrade = ws_headers_get(&req->headers, "Upgrade");
    return (upgrade && strcasecmp(upgrade, "websocket") == 0);
}

int main(int argc, char **argv)
{
    ws_options_t opt;
    int listen_fd = -1;

    init_options(&opt);

    if (parse_options(argc, argv, &opt) < 0) {
        return 2;
    }

    /* Features not yet implemented in native C runtime */
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
        fprintf(stderr, "error: selected compatibility options are parsed but not implemented in native C runtime yet\n");
        return 2;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    listen_fd = create_listener(opt.listen_host, opt.listen_port, opt.source_is_ipv6);
    if (listen_fd < 0) {
        perror("listen");
        free(opt.listen_host);
        free(opt.target_host);
        return 1;
    }

    fprintf(stderr, "websockify-codex listening on %s:%d -> %s:%d\n",
            (opt.listen_host && opt.listen_host[0]) ? opt.listen_host : "0.0.0.0",
            opt.listen_port,
            opt.target_host,
            opt.target_port);

    while (!g_stop) {
        int client_fd;
        http_request_t req;

        client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            break;
        }

        http_request_init(&req);
        if (read_http_request(client_fd, &req) == 0) {
            if (is_websocket_upgrade(&req)) {
                int target_fd;
                ws_conn_t ws;
                ws_fd_ctx_t fd_ctx;
                ws_buf_t prefetched;

                if (!req.method || strcmp(req.method, "GET") != 0) {
                    const char resp[] = "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n";
                    send(client_fd, resp, sizeof(resp) - 1, 0);
                } else {
                    target_fd = connect_target(opt.target_host, opt.target_port);
                    if (target_fd < 0) {
                        perror("connect_target");
                    } else {
                        ws_conn_init(&ws, 0);
                        ws_buf_init(&prefetched);
                        fd_ctx.fd = client_fd;
                        ws.ctx.user_data = &fd_ctx;
                        ws.ctx.io_send = ws_fd_send;

                        if (ws_accept(&ws, &req.headers) == WS_OK) {
                            if ((size_t)req.consumed < req.raw.len) {
                                ws_buf_append(&prefetched, req.raw.data + req.consumed, req.raw.len - (size_t)req.consumed);
                            }
                            (void)proxy_connection(client_fd, target_fd, &ws, &prefetched);
                        } else {
                            const char resp[] = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
                            send(client_fd, resp, sizeof(resp) - 1, 0);
                        }

                        ws_buf_free(&prefetched);
                        ws_conn_free(&ws);
                        close(target_fd);
                    }
                }
            } else {
                (void)serve_web_request(client_fd, &opt, &req);
            }
        }

        http_request_free(&req);
        close(client_fd);

        if (opt.run_once) {
            break;
        }
    }

    close(listen_fd);
    free(opt.listen_host);
    free(opt.target_host);
    return 0;
}
