CC      = gcc
CFLAGS  = -g
RM      = rm -f

default: all

all: Hello

Hello: normal_web_server.c
	gcc normal_web_server.c -o normal_web_server

clean veryclean:
	$(RM) normal_web_server
