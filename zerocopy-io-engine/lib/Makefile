.PHONY: clean

all: pslib.a

pslib.a: pslib.c
#	gcc -O1 -c -g -Wall -o pslib.o pslib.c
	gcc -O2 -c -g -Wall -o pslib.o pslib.c
	ar rcs libps.a pslib.o

clean:
	rm -f *.o *.a
