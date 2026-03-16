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
	rm -f $(OBJ) $(TARGET) archive.tar test.txt
	rm -rf successful_crashes

.PHONY: clean