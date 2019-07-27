
CC=clang
CFLAGS=-O0 -g -Wall -Werror
CPPFLAGS=-I/usr/local/include -I/usr/local/include/p11-kit-1
LDFLAGS=-Wl,-rpath /usr/local/lib/pkcs11
LIBS=/usr/local/lib/pkcs11/opensc-pkcs11.so -lssl -lcrypto

OBJS=login_yubikey_piv.o

login_yubikey_piv: $(OBJS)
	$(CC) -o "$@" $(OBJS) $(LDFLAGS) $(LIBS)

.c.o:
	$(CC) -c $(CFLAGS) $(CPPFLAGS) "$<" -o "$@"
clean:
	rm *.o
