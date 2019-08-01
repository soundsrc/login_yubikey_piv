CC=clang
CFLAGS=-O0 -g -Wall -Werror
CPPFLAGS=-I/usr/local/include -I/usr/local/include/p11-kit-1
LDFLAGS=-Wl,-rpath /usr/local/lib/pkcs11
LIBS=/usr/local/lib/pkcs11/opensc-pkcs11.so -lssl -lcrypto
DESTDIR=/usr/local

OBJS=login_yubikey_piv.o

all: login_yubikey_piv

login_yubikey_piv: $(OBJS)
	$(CC) -o "$@" $(OBJS) $(LDFLAGS) $(LIBS)

install: login_yubikey_piv
	install -D login_yubikey_piv $(DESTDIR)/libexec/auth/login_yubikey_piv

.c.o:
	$(CC) -c $(CFLAGS) $(CPPFLAGS) "$<" -o "$@"
clean:
	rm login_yubikey_piv *.o
