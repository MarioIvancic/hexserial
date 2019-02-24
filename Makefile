# makefile for linux

hexserial: hexserial.c hexfile.c hexfile.h
	$(CC) -O2 -g -o hexserial hexserial.c hexfile.c

install:
	sudo install -g root -o root -p hexserial /usr/local/bin/hexserial

clean:
	rm -f *.o hexserial

.PHONY: install clean
