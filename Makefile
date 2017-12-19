# makefile for linux

hexserial: hexserial.c hexfile.c hexfile.h
	$(CC) -O2 -g -o hexserial hexserial.c hexfile.c

install:
	install -C -g root -o root -m rwxr-xr-x -p hexserial /usr/local/bin/hexserial


.PHONY: install
