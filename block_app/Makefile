PRO_DIR := .
OUTPUT_DIR := $(PRO_DIR)/output
SRC_DIR := $(PRO_DIR)/src
CC := /home/test/Documents/buildroot-2015.05/output/host/usr/bin/mips-buildroot-linux-uclibc-gcc
# CC := gcc

LIB_DIR := $(PRO_DIR)/include
BIN := $(PRO_DIR)/bin
DATA_DIR := $(PRO_DIR)/data
DOMAIN_DIR := $(PRO_DIR)/domain
OTHER_DIR := $(PRO_DIR)/ip_db/other

CFLAGS := -g -std=c99
LDFLAGS := -lm -lnetfilter_queue -pthread

SRC_FILES := $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES := $(SRC_FILES:$(SRC_DIR)/%.c=$(OUTPUT_DIR)/%.o)

all: $(OBJ_FILES) | $(BIN) $(OUTPUT_DIR)
	$(CC) $(OBJ_FILES) -o $(BIN)/app $(LDFLAGS)

$(OUTPUT_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I$(LIB_DIR)

$(BIN):
	mkdir -p $(BIN)

$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)

clean:
	rm -rf $(OUTPUT_DIR)/*
	rm -rf $(BIN)/*
	rm -rf $(DOMAIN_DIR)/*
	rm -rf $(OTHER_DIR)/*
