COMMENT =	yubikey piv login authenticator

DISTNAME =	login_yubikey_piv-1.0.0
REVISION =	0

GH_ACCOUNT =	soundsrc
GH_PROJECT =	login_yubikey_piv
GH_COMMIT =	master

CATEGORIES =	security

# BSD
PERMIT_PACKAGE_CDROM = Yes

# uses pledge()

# "make port-lib-depends-check" can help
WANTLIB = ssl crypto

RUN_DEPENDS =	security/opensc

NO_TEST = Yes

.include <bsd.port.mk>
