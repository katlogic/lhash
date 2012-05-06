OBJ=lhash.o crc32.o sha1.o sha2.o md5.o rand.o
CFLAGS=-I/usr/include/lua5.1 -O2 -Wall -fPIC 
.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
lhash.so: $(OBJ)
	$(CC) -shared $(OBJ) -o $@
clean:
	rm -f *.o *.so
