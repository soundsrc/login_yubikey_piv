/*
	Copyright (c) 2019 Sound <sound@sagaforce.com>

	Permission to use, copy, modify, and distribute this software for any
	purpose with or without fee is hereby granted, provided that the above
	copyright notice and this permission notice appear in all copies.

	THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
	WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
	MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
	ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
	WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
	ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
	OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <dlfcn.h>
#include <login_cap.h>
#include <pwd.h>
#include <readpassphrase.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <p11-kit/pkcs11.h>

#define COUNT_OF(x) (sizeof(x) / sizeof(x[0]))

#define AUTHORIZED_KEY_PATH "/.yubikey/authorized_keys"

#define DIGEST_ALGORITHM EVP_sha256()

#define DIGEST_LENGTH SHA256_DIGEST_LENGTH

enum LoginMode { LOGINMODE_LOGIN, LOGINMODE_CHALLENGE, LOGINMODE_RESPONSE };

enum SignMode { SIGNMODE_RSA, SIGNMODE_ECDSA };

/*
 * Trigger the yubikey to sign the challenge and produce a signature.
 * A PIN prompt will also be presented to unlock the yubikey.
 */
static int yubikey_sign_challenge(const uint8_t *challenge, size_t challenge_len, uint8_t *signature,
				  size_t *signature_len, enum SignMode *sign_mode) {
	int ret = 0;

	CK_FUNCTION_LIST_PTR p11 = NULL;
	CK_RV rc;
	CK_ULONG num_slots;
	CK_SESSION_HANDLE session;
	CK_SLOT_ID_PTR slot_ids;

	char *password;
	size_t password_len;
	char password_buf[256];

	CK_OBJECT_CLASS pk_class = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE find_private_key_attributes[] = {{CKA_CLASS, &pk_class, sizeof(pk_class)}};

	CK_KEY_TYPE key_type;
	CK_ATTRIBUTE find_key_type_attributes[] = {{CKA_KEY_TYPE, &key_type, sizeof(key_type)}};
	CK_ULONG num_keys;

	CK_OBJECT_HANDLE private_key;
	CK_MECHANISM mechanisms = {CKM_ECDSA, NULL_PTR};

	CK_TOKEN_INFO token_info;

	CK_BYTE challenge_digest[DIGEST_LENGTH];
	EVP_MD_CTX ctx;
	int challenge_digest_len;

	p11 = NULL;
	if (C_GetFunctionList(&p11) != CKR_OK) {
		syslog(LOG_ERR, "C_GetFunctionList(): Failed to obtain function list.");
		goto failed0;
	}

	rc = p11->C_Initialize(NULL_PTR);
	if (rc != CKR_OK) {
		syslog(LOG_ERR, "C_Initialize(): Failed to initialize PCKS11 "
				"interface.");
		goto failed0;
	}

	rc = p11->C_GetSlotList(FALSE, NULL_PTR, &num_slots);
	if (rc != CKR_OK) {
		syslog(LOG_ERR, "C_GetSlotList(): Failed to query slot count.");
		goto failed1;
	}

	if (num_slots == 0) {
		fprintf(stderr, "Yubikey not detected.\n");
		syslog(LOG_ERR, "No slots are available. Key not inserted?");
		goto failed1;
	}

	slot_ids = (CK_SLOT_ID_PTR)malloc(num_slots * sizeof(CK_SLOT_ID));
	if (!slot_ids) {
		syslog(LOG_ERR, "Out of memory.");
		goto failed1;
	}

	rc = p11->C_GetSlotList(FALSE, slot_ids, &num_slots);
	if (rc != CKR_OK) {
		syslog(LOG_ERR, "C_GetSlotList(): Failed to retrieve slot list.");
		goto failed2;
	}

	rc = p11->C_OpenSession(slot_ids[0], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session);
	if (rc != CKR_OK) {
		syslog(LOG_ERR, "C_OpenSession(): Failed to open session.");
		goto failed2;
	}

	// read in the pin
	if ((password = readpassphrase("PIN:", password_buf, sizeof(password_buf), RPP_ECHO_OFF)) == NULL) {
		syslog(LOG_ERR, "readpassphrase(): Failed to read password.");
		goto failed3;
	}
	password_len = strlen(password);

	rc = p11->C_Login(session, CKU_USER, password, password_len);
	switch (rc) {
	case CKR_OK:
		break;
	case CKR_PIN_INCORRECT:
	case CKR_PIN_LEN_RANGE:
	case CKR_PIN_INVALID:
		if (p11->C_GetTokenInfo(slot_ids[0], &token_info) == CKR_OK) {
			if (token_info.flags & CKF_USER_PIN_FINAL_TRY) {
				fprintf(stderr, "Only one more retry attempt "
						"can be made before PIN "
						"becomes locked.\n");
			}
		}
		goto failed3;
	case CKR_PIN_LOCKED:
		fprintf(stderr, "PIN is locked.\n");
		goto failed3;
	case CKR_PIN_EXPIRED:
		fprintf(stderr, "PIN has expired.\n");
		goto failed3;
	default:
		syslog(LOG_ERR, "C_Login(): Failed to connect to yubikey.");
		goto failed3;
	}
	explicit_bzero(password_buf, sizeof(password_buf));

	rc = p11->C_FindObjectsInit(session, find_private_key_attributes, COUNT_OF(find_private_key_attributes));
	if (rc != CKR_OK) {
		syslog(LOG_ERR, "C_FindObjectsInit(): Fail to find initiate "
				"object find.");
		goto failed4;
	}

	rc = p11->C_FindObjects(session, &private_key, 1, &num_keys);
	if (rc != CKR_OK) {
		syslog(LOG_ERR, "C_FindObjects(): Fail to find private key.");
		goto failed4;
	}

	if (num_keys != 1) {
		fprintf(stderr, "No private key in slot.\n");
		goto failed4;
	}

	rc = p11->C_GetAttributeValue(session, private_key, find_key_type_attributes,
				      COUNT_OF(find_key_type_attributes));
	if (rc != CKR_OK) {
		syslog(LOG_ERR, "C_GetAttributeValue(): Fail to determine "
				"private key type.");
		goto failed4;
	}

	switch (key_type) {
	case CKK_ECDSA:
		*sign_mode = SIGNMODE_ECDSA;
		break;
	case CKK_RSA:
		*sign_mode = SIGNMODE_RSA;
		break;
	default:
		syslog(LOG_ERR, "Unsupported private key type.");
		goto failed4;
	}

	EVP_MD_CTX_init(&ctx);
	if (!EVP_DigestInit(&ctx, DIGEST_ALGORITHM)) {
		syslog(LOG_ERR, "EVP_DigestInit(): Digest failure.");
		goto failed4;
	}
	if (!EVP_DigestUpdate(&ctx, challenge, challenge_len)) {
		syslog(LOG_ERR, "EVP_DigestUpdate(): Digest failure.");
		goto failed4;
	}
	if (!EVP_DigestFinal(&ctx, challenge_digest, &challenge_digest_len)) {
		syslog(LOG_ERR, "EVP_DigestFinal: Digest failure.");
		goto failed4;
	}

	rc = p11->C_SignInit(session, &mechanisms, private_key);
	if (rc != CKR_OK) {
		syslog(LOG_ERR, "C_SignInit(): Failed to initialize key signing.");
		goto failed4;
	}

	rc = p11->C_Sign(session, challenge_digest, challenge_digest_len, signature, signature_len);
	if (rc != CKR_OK) {
		syslog(LOG_ERR, "C_Sign(): Failed to sign challenge.");
		goto failed4;
	}

	ret = 1;
failed4:
	p11->C_Logout(session);
failed3:
	explicit_bzero(password_buf, sizeof(password_buf));
	p11->C_CloseSession(session);
failed2:
	free(slot_ids);
failed1:
	p11->C_Finalize(NULL_PTR);
failed0:
	return ret;
}

static int authenticate_against_certificates(const char *username, const unsigned char *data, size_t data_len,
					     const unsigned char *signature, size_t signature_len,
					     enum SignMode sign_mode) {
	struct passwd *pw;
	char authorized_key_path[1024];
	char line[1024];
	BIO *mem;
	X509 *cert;
	EVP_PKEY *public_key;
	int public_key_type;
	FILE *fp;
	EVP_MD_CTX ctx;
	int verified = 0;

	static const char begin_tag[] = "-----BEGIN CERTIFICATE-----";
	static const char end_tag[] = "-----END CERTIFICATE-----";

	// Determine the path to $HOME/.yubikey/authorized_keys
	// TODO: permission check
	setpwent();

	while ((pw = getpwent())) {
		if (!strcmp(pw->pw_name, username)) {
			if (strlcpy(authorized_key_path, pw->pw_dir, sizeof(authorized_key_path)) >=
			    sizeof(authorized_key_path)) {
				syslog(LOG_ERR, "User home directory path is too long.");
				endpwent();
				return 0;
			}

			if (strlcat(authorized_key_path, AUTHORIZED_KEY_PATH, sizeof(authorized_key_path)) >=
			    sizeof(authorized_key_path)) {
				syslog(LOG_ERR, "Path to authorized_keys is too long.");
				endpwent();
				return 0;
			}

			break;
		}
	}

	endpwent();

	if (!pw) {
		syslog(LOG_ERR, "User '%s' was not found.", username);
		return 0;
	}

	fp = fopen(authorized_key_path, "r");
	if (!fp)
		return 0;

	// Loop through each certificate in the authorized_keys file and
	// authenticate
	mem = NULL;
	while (verified != 1 && fgets(line, sizeof(line), fp)) {
		// skip any lines that does not begin with the tag
		if (strncmp(line, begin_tag, sizeof(begin_tag) - 1))
			continue;

		// read all lines between the begin and end tags
		mem = BIO_new(BIO_s_mem());
		if (!mem) {
			syslog(LOG_ERR, "Out of memory.");
			goto failed0;
		}
		BIO_puts(mem, line);

		while (fgets(line, sizeof(line), fp)) {
			BIO_puts(mem, line);
			if (!strncmp(line, end_tag, sizeof(end_tag) - 1))
				break;
		}

		BIO_flush(mem);

		if (!(cert = PEM_read_bio_X509(mem, NULL, 0, NULL))) {
			syslog(LOG_ERR, "Invalid certificate found.");
			continue;
		}

		public_key = X509_get0_pubkey(cert);
		if (!public_key) {
			syslog(LOG_ERR, "No public key found in certificate.");
			continue;
		}

		public_key_type = EVP_PKEY_base_id(public_key);
				
		EVP_MD_CTX_init(&ctx);
		if (!EVP_VerifyInit(&ctx, DIGEST_ALGORITHM)) goto failed1;
		if (!EVP_VerifyUpdate(&ctx, data, data_len)) goto failed1;

		if (public_key_type == EVP_PKEY_EC && sign_mode == SIGNMODE_ECDSA) {
			unsigned char *der_sig;

			ECDSA_SIG ecdsa_sig;
			size_t sig_component_len = signature_len / 2;
			
			ecdsa_sig.r = BN_bin2bn(signature, sig_component_len, NULL);
			if (!ecdsa_sig.r) {
				syslog(LOG_ERR, "BN_bin2bn(): error.");
				goto failed1;
			}

			ecdsa_sig.s = BN_bin2bn(signature + sig_component_len, sig_component_len, NULL);
			if (!ecdsa_sig.s) {
				syslog(LOG_ERR, "BN_bin2bn(): error.");
				goto failed2;
			}
			int der_sig_len = i2d_ECDSA_SIG(&ecdsa_sig, NULL);

			der_sig = (unsigned char *)malloc(der_sig_len);
			if (!der_sig) {
				syslog(LOG_ERR, "Out of memory.");
				goto failed3;
			}

			unsigned char *der_sig_ptr = der_sig;
			i2d_ECDSA_SIG(&ecdsa_sig, &der_sig_ptr);

			verified = EVP_VerifyFinal(&ctx, der_sig, der_sig_len, public_key);

			free(der_sig);
failed3:
			BN_free(ecdsa_sig.s);
failed2:
			BN_free(ecdsa_sig.r);
		}
failed1:
		BIO_free(mem);
	}
failed0:
	fclose(fp);

	return verified;
}

static void print_usage() { fprintf(stderr, "usage: login_yubikey_piv [-d] [-v] [-s login] <username>\n"); }

int main(int argc, char *argv[]) {
	uint8_t challenge[256];
	uint8_t signature[512];
	size_t signature_len = sizeof(signature);
	enum SignMode sign_mode;
	enum LoginMode login_mode;
	FILE *f = NULL;
	const char *username;
	int ret = EXIT_FAILURE;
	int ch;

	SSL_library_init();

	if (pledge("stdio unix getpw tty rpath cpath prot_exec dns", NULL) == -1) {
		syslog(LOG_AUTH | LOG_ERR, "pledge: %m");
		goto failed0;
	}

	openlog(NULL, LOG_ODELAY, LOG_AUTH);

	while ((ch = getopt(argc, argv, "dv:s:")) != -1) {
		switch (ch) {
		case 'd':
			f = stdout;
			break;
		case 'v':
			break;
		case 's':
			if (!strcmp(optarg, "login"))
				login_mode = LOGINMODE_LOGIN;
			else if (!strcmp(optarg, "response"))
				login_mode = LOGINMODE_RESPONSE;
			else if (!strcmp(optarg, "challenge"))
				login_mode = LOGINMODE_CHALLENGE;
			else {
				syslog(LOG_ERR, "%s: invalid service", optarg);
				goto failed1;
			}
			break;
		default:
			print_usage();
			goto failed1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 2 && argc != 1) {
		print_usage();
		goto failed1;
	}

	username = argv[0];

	if (f == NULL && (f = fdopen(3, "r+")) == NULL) {
		syslog(LOG_ERR, "user %s: fdopen: %m", username);
		goto failed1;
	}

	if (login_mode != LOGINMODE_LOGIN) {
		fprintf(f, "%s\n", BI_REJECT);
		goto failed1;
	}

	// generate random bytes for the challenge
	arc4random_buf(challenge, sizeof(challenge));

	// trigger the yubikey to produce a signature
	if (!yubikey_sign_challenge(challenge, sizeof(challenge), signature, &signature_len, &sign_mode))
		goto failed1;

	if (pledge("stdio getpw rpath", NULL) == -1) {
		syslog(LOG_AUTH | LOG_ERR, "pledge: %m");
		goto failed1;
	}

	if (!authenticate_against_certificates(username, challenge, sizeof(challenge), signature, signature_len,
					       sign_mode))
		goto failed1;

	fprintf(f, "%s\n", BI_AUTH);

	ret = EXIT_SUCCESS;
failed1:
	closelog();
failed0:
	return ret;
}
