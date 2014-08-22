LIBS = -lps
LIB_DIR = -L../../lib

.PHONY: clean

all: rxdump

rxdump: rxdump.c
#	gcc -O1 -g -Wall -o rxdump rxdump.c $(LIB_DIR) $(LIBS)
	gcc -O2 -Wall -o rxdump rxdump.c $(LIB_DIR) $(LIBS)

clean:
	rm -f rxdump
