CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c99 -D_POSIX_C_SOURCE=200809L
INCLUDES = -Iinclude -Itests
SRC = src/base64.c src/http_parser.c src/sha1.c src/util.c src/websocket.c
OBJ = $(SRC:.c=.o)
BIN = websockify
BIN_OBJ = src/main.o

TEST_BIN = tests/test_websocket

.PHONY: all clean test

all: $(BIN) $(TEST_BIN)

$(BIN): $(BIN_OBJ) $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_BIN): $(OBJ) tests/test_websocket.o
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

test: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	rm -f $(OBJ) $(BIN_OBJ) $(BIN) tests/test_websocket.o $(TEST_BIN)
