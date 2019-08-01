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


# Setting up the Yubikey

Authentication works using slot 9a of the Yubikey PIV interface.
See the Yubico website:

 * https://developers.yubico.com/PIV/

Follow the guides to setup a PIN, PUK and management keys.
Load slot9a with a private key and certificate.
The Yubikey Manager makes this process very easy.

TODO: detailed process for setting up slot

# Setting up authentication

Dump out a certificate from slot 9a.

```
yubico-piv-tool -aread-cert -s9a
```

Add entry to: 

```
$HOME/.yubikey/authorized_keys
```

