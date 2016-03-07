CFLAGS=-I/usr/include/lua5.1 -O2 -Wall -fPIC 
all: sha1.so sha2.so sha3.so md5.so
.o.so:
	$(CC) $(CFLAGS) -shared $< -o $@
.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	rm -f *.o *.so
