# websockify-codex

A standalone **ANSI C rewrite** of [websockify](https://github.com/novnc/websockify), created by [OpenAI Codex](https://openai.com/index/openai-codex/). It proxies WebSocket connections to plain TCP backends and serves the same purpose as the original Python implementation — most notably enabling browser-based VNC clients (e.g. [noVNC](https://novnc.com)) to connect to VNC servers.

## Features

- Single static binary, no runtime dependencies
- Non-blocking event loop with `select()`
- HTTP upgrade handshake (RFC 6455)
- HyBi WebSocket framing (encode/decode, ping/pong)
- Static file serving (`--web`)
- Per-connection concurrency with periodic verbose stats
- CLI syntax compatible with Python websockify

## Build

```sh
make
make test
```

Requires a C99-capable compiler (`cc` / `gcc` / `clang`) and POSIX headers.

## Usage

```sh
./websockify [options] [source_addr:]source_port target_addr:target_port
./websockify [options] --token-plugin=CLASS [source_addr:]source_port
./websockify [options] --unix-target=FILE [source_addr:]source_port
./websockify [options] [source_addr:]source_port -- WRAP_COMMAND_LINE
```

### Common options

| Option | Description |
|---|---|
| `--web DIR` | Serve static files from `DIR` alongside the WebSocket proxy |
| `--verbose` | Enable verbose logging |
| `--log-file FILE` | Write log output to `FILE` |
| `--record FILE` | Record WebSocket traffic to `FILE` |
| `--daemon` | Run in the background |

Run `./websockify --help` for the full option list.

### Quick start — noVNC + VNC

```sh
# Proxy WebSocket port 6080 → VNC server on localhost:5900
./websockify 6080 localhost:5900

# With built-in noVNC web serving
./websockify --web /path/to/noVNC 6080 localhost:5900
```

## Implementation status

| Feature | Status |
|---|---|
| Direct TCP proxy | Implemented |
| HTTP/WebSocket upgrade | Implemented |
| Static file serving (`--web`) | Implemented |
| HyBi frame encode/decode | Implemented |
| Ping/pong keepalive | Implemented |
| Non-blocking event loop | Implemented |
| TLS/SSL | Not implemented |
| Unix socket target | Not implemented |
| inetd mode | Not implemented |
| Token plugins | Not implemented (parsed, returns error) |
| Wrap command | Not implemented (parsed, returns error) |

## Tests

The C test suite is a behavioural port of the Python websocket unit tests:

```sh
make test
# runs tests/test_websocket
```

## License

LGPLv3 — same as the original [novnc/websockify](https://github.com/novnc/websockify). See [LICENSE](LICENSE).
