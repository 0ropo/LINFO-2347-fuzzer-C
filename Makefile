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
	rm -f $(OBJ) $(TARGET) archive.tar test.txt success*
	rm -f %s* A B C D \ * -1 0 8888* 9999* +123 -000* 0x123

.PHONY: clean
