COMMENT =	yubikey piv login authenticator

V =		1.0.0
DISTNAME =	login_yubikey_piv-${V}

GH_ACCOUNT =	soundsrc
GH_PROJECT =	login_yubikey_piv
GH_COMMIT =	master

CATEGORIES =	sysutils security

# ISC
PERMIT_PACKAGE_CDROM = Yes

# uses pledge()

# "make port-lib-depends-check" can help
WANTLIB = c ssl crypto

LIB_DEPENDS =	security/opensc

NO_TEST = Yes

.include <bsd.port.mk>
