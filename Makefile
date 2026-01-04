CC = gcc
LD = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lssl -lcrypto
SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)
TARGET = hyprc

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) $^ -o $@

$(OBJS): $(SRCS)
	$(CC) $(CFLAGS) $^ -c

clean:
	rm $(OBJS)

.PHONY = clean
