CC = gcc
CFLAGS = -Wall -Wextra -std=c11

SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)

TARGET = fuzzer

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: clean