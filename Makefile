# makefile for linux

HexSerial-1.1: hexserial.c hexfile.c hexfile.h
	$(CC) -O2 -g -o HexSerial-1.1 hexserial.c hexfile.c


