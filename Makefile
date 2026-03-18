CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -D_POSIX_C_SOURCE=200809L

SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)

TARGET = fuzzer

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET) archive.tar test.txt success* "/%x/%n/%s/%p" "%s%s%s%s%s%s%s" "A\x00B\x00C\x00D" "88888888" "99999999999" " 123" "123 " "+123" ./-000001 ./-200 "0x123" "\000123" "0000000" name

.PHONY: clean