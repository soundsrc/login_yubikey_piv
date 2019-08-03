PROG=		login_yubikey_piv
SRCS=		login_yubikey_piv.c
MAN=		login_yubikey_piv.8

CFLAGS=		-O2 -I/usr/local/include -I/usr/local/include/p11-kit-1 -Wall -Werror
LDFLAGS=	-Wl,-rpath /usr/local/lib/pkcs11
LDADD=		/usr/local/lib/pkcs11/opensc-pkcs11.so -lssl -lcrypto

BINDIR=		$(LOCALBASE)/libexec/auth
BINOWN=		root
BINGRP=		auth

beforeinstall:
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m ${DIRMODE} ${DESTDIR}${BINDIR}
	echo $(MANDIR)

.include <bsd.prog.mk>
