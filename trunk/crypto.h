#ifndef CRYPTO_H
#define CRYPTO_H

#define AEKE_CIPHER 	SN_aes_128_cbc

#define DH_GENERATOR	"05"
#define DH_PRIME	"9A4AF986C217EE1E1FBD9E6A8362989B15F1BB67EA1606D90A23D995619550DE" \
			"D4497A3E34FCC983BC657B4C66A8BEB56CC032977E3B244CB47CB47A8BD61D4B" \
			"1FEAAC2F778A5588611C81A93BF2D295DC932AFAB97B70944736F089E01632C5" \
			"F0977DE9A1175387F519D055A26E3AC5ED3C9BA95D7CF3CAAF7D71FE6706068B"

extern void initCrypto(void);
extern void cleanupCrypto(void);

/* Generic functions. */

extern void makeHash(const unsigned char *input, unsigned int input_len,
		     unsigned char *output);

extern int initPkeyPair(Socket *s);
extern int generateSessionKey(Socket *s);
extern void cleanupConnCrypto(Socket *s);

/* Client functions. */

extern void generateClientVerifier(Socket *s);
extern int checkServerAck(Socket *s);

/* Server functions. */

extern int verifyClient(Socket *cd);

#endif /* CRYPTO_H */
