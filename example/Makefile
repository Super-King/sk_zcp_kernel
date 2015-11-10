PWD = $(shell pwd)
ALL = receive send forward
DEBUG = -DDEBUG

INCLUDES = $(PWD)/../include
LIBS = $(PWD)/../lib

CC  = gcc
CFLAGS = -I$(INCLUDES) -L$(LIBS) -lzcopy -Wl,-rpath,../lib

RM = rm
RMFLAGS = -rf


.PHONY: all clean

all : $(ALL)

receive: receive.c
	$(CC) -o $@ $^ $(DEBUG) $(CFLAGS)
send: send.c
	$(CC) -o $@ $^ $(DEBUG) $(CFLAGS)
forward: forward.c
	$(CC) -o $@ $^ $(DEBUG) $(CFLAGS)
clean:
	$(RM)  $(RMFLAGS) $(ALL)
