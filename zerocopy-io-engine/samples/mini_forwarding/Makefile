LIBS = -lps
LIB_DIR = -L../../lib

.PHONY: clean

all: mini_forwarding

mini_forwarding: mini_forwarding.c
#	gcc -O1 -g -Wall -o rxdump rxdump.c $(LIB_DIR) $(LIBS)
	gcc -O2 -g -Wall -o mini_forwarding mini_forwarding.c $(LIB_DIR) $(LIBS)

clean:
	rm -f mini_forwarding
