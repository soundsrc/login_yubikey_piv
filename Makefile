PROG=		login_yubikey_piv
SRCS=		login_yubikey_piv.c

CFLAGS=		-O2 -I/usr/local/include -I/usr/local/include/p11-kit-1 -Wall -Werror
LDFLAGS=	-Wl,-rpath /usr/local/lib/pkcs11
LDADD=		/usr/local/lib/pkcs11/opensc-pkcs11.so -lssl -lcrypto

BINDIR=		/usr/libexec/auth

.include <bsd.prog.mk>
