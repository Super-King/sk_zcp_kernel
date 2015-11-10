PWD = $(shell pwd)
ALL = libzcopy.so
DEBUG = -DDEBUG

INCLUDES = -I$(PWD)/../include -I$(PWD)/../driver
LIBS =

CC  = gcc
CFLAGS =
LIBFLAGS = $(INCLUDES) -shared -fPIC -Wall -lpthread

RM = rm
RMFLAGS = -rf


.PHONY: all clean

all : $(ALL)

libzcopy.so: libzcopy.c
	$(CC) -o $@ $^ $(DEBUG) $(LIBFLAGS)
clean:
	$(RM)  $(RMFLAGS) $(ALL)
