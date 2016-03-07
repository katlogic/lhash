.SUFFIXES: .c .so .o
CFLAGS=-I/usr/local/include/lua/5.3 -L/usr/local/lib -O2 -Wall -llua53
all: sha1.so sha2.so sha3.so md5.so
.c.so:
	$(CC) $(CFLAGS) -shared $< -o $@
clean:
	rm -f *.o *.so
