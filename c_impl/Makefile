# Compiler
CC := gcc

# Target executable
TARGET := make_quote

# Source file
SRC := make_quote.c

# OpenSSL version
OPENSSL_VERSION := 3.3.2

# Find OpenSSL installation directory
OPENSSL_DIR := $(shell find /opt/homebrew/Cellar/openssl@3 -name $(OPENSSL_VERSION) -type d)

# If OpenSSL directory is not found, print an error
ifeq ($(OPENSSL_DIR),)
$(error OpenSSL $(OPENSSL_VERSION) not found in /opt/homebrew/Cellar/openssl@3)
endif

# Include and library paths
INCLUDES := -I$(OPENSSL_DIR)/include
LIBPATH := -L$(OPENSSL_DIR)/lib

# Libraries
LIBS := -lssl -lcrypto

# Compiler flags
CFLAGS := $(INCLUDES)
LDFLAGS := $(LIBPATH) $(LIBS)

# Default target
all: $(TARGET)

# Compile the target
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Clean up
clean:
	rm -f $(TARGET)

.PHONY: all clean
