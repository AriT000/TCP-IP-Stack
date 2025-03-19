CC = gcc
CFLAGS = -Wall -Wextra
TARGET = tcpip_stack

all: $(TARGET)

$(TARGET): simple-tcpip-stack.c
	$(CC) $(CFLAGS) -o $(TARGET) simple-tcpip-stack.c

clean:
	rm -f $(TARGET)
