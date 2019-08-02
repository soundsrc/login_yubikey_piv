# login_yubikey_piv

* IN DEVELOPMENT, DO NOT USE *

YubiKey login authentication for OpenBSD using the PIV interface.
This is mainly for personal use, no support will be provided.

# Installation

This tool depends on opensc, which can be obtained through ports.
```
pkg_add opensc
```

Ensure the PC/SC smart card service is enabled and running.

```
rcctl enable pcscd
rcctl start pcscd
```

If you are also using the GPG smartcard interface on your Yubikey, ccid
should be disabled in:

$HOME/.gnupg/scdaemon.conf
```
disable-ccid
```

# Setup login.conf

Add yubikey_piv as an additional method for login. For example:

/etc/login.conf
```
auth-defaults:auth=passwd,skey,yubikey_piv:
```

Put yubikey_piv to the front of the list to set it as the default method.
It is recommended that you keep passwd authentication as a backup.

# Setting up the Yubikey

Authentication works using slot 9a of the Yubikey PIV interface.
See the Yubico website:

 * https://developers.yubico.com/PIV/

Follow the guides to setup a PIN, PUK and management keys.

# Create, generate or import certificate on slot 9a

If using the YubiKey Manager tool, use the user interface to
generate a key on slot 9a (Authentication Slot).

Alternatively, follow steps 1-3 in the SSH with PIV guide from Yubico:

 * https://developers.yubico.com/PIV/Guides/SSH_with_PIV_and_PKCS11.html

The same keys used for SSH can also be used here.

# Setting up authentication

Dump out a certificate from slot 9a.

```
yubico-piv-tool -aread-cert -s9a
```

On the host server, append the certiciate to:

```
$HOME/.yubikey/authorized_keys
```

