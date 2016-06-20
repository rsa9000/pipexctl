
CFLAGS+= -Wall

all: pipexctl

pipexctl: pipexctl.c

clean:
	rm -f pipexctl
