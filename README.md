# websockify-codex

ANSI C-focused WebSocket proxy implementation with a standalone `websockify` executable.

## Scope

This directory has two deliverables:

- `websockify` binary: native C WebSocket-to-TCP proxy.
- C protocol core + tests: handshake/frame logic validated by a direct test port.

The C protocol test scope currently covers:

- server accept handshake validation
- subprotocol negotiation behavior
- ping/pong frame generation
- HyBi frame encode/decode behavior

## Build and test

```sh
make -C websockify-codex
make -C websockify-codex test
```

This builds:

- `websockify-codex/websockify` (native proxy binary)
- `websockify-codex/tests/test_websocket` (C test binary)

And runs:

- `websockify-codex/tests/test_websocket.c`

## Run

```sh
./websockify-codex/websockify --help
./websockify-codex/websockify 6080 localhost:5900
```

CLI syntax now matches Python websockify call patterns:

```sh
./websockify-codex/websockify [options] [source_addr:]source_port target_addr:target_port
./websockify-codex/websockify [options] --token-plugin=CLASS [source_addr:]source_port
./websockify-codex/websockify [options] --unix-target=FILE [source_addr:]source_port
./websockify-codex/websockify [options] [source_addr:]source_port -- WRAP_COMMAND_LINE
```

Runtime implementation status:

- Argument parsing and validation mirrors Python option semantics.
- Native proxy data path is implemented for direct TCP target mode.
- `--web` static file serving and mixed HTTP/WebSocket mode are implemented.
- Some Python runtime features are parsed but currently return explicit `not implemented` errors in C (TLS stack, unix/inetd, wrap, plugin execution, syslog/libserver, `--web-auth`).

The C tests are a one-to-one behavioral port of Python websocket unit tests in:

- `tests/test_websocket.py`

## Notes

- Build is configured with `-std=c99` and POSIX declarations enabled for string helpers.
- Test harness is self-contained in `tests/test_common.h`.
