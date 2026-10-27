# dnspark — Makefile
# Nativo:      make
# Cross (host): make CROSS=aarch64-linux-gnu-
# Buildroot:   se compila dentro de la imagen/overlay (ver README)

CROSS   ?=
CC      := $(CROSS)gcc
CFLAGS  := -std=c99 -O2 -Wall -Wextra -D_POSIX_C_SOURCE=200809L
LDFLAGS :=

SRC := buildroot/package/dnspark/main.c
BIN := dnspark

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

clean:
	rm -f $(BIN)

.PHONY: clean
