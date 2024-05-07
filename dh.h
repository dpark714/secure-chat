/* Diffie Hellman key exchange + HKDF */
#pragma once
#include <gmp.h>
#include "keys.h"

extern mpz_t q; /** "small" prime; should be 256 bits or more */
extern mpz_t p; /** "large" prime; should be 2048 bits or more, with q|(p-1) */
extern mpz_t g; /** generator of the subgroup of order q */
extern size_t qBitlen; /** length of q in bits */
extern size_t pBitlen; /** length of p in bits */
extern size_t qLen; /** length of q in bytes */
extern size_t pLen; /** length of p in bytes */

#ifdef __cplusplus
extern "C" {
#endif
/* NOTE: you must call init or initFromScratch before doing anything else. */
/** Try to read q,p,g from a file: */
int init(const char* fname);
/** Generate fresh Diffie Hellman parameters.  This is a somewhat
 * expensive computation, so it's best to save and reuse params.
 * Prints generated parameters to stdout. */
int initFromScratch(size_t qBitlen, size_t pBitlen);
/** set sk to a random exponent (this part is secret) and set
 * pk to g^(sk) mod p */
int dhGen(mpz_t sk, mpz_t pk);
/** same as dhGen, but accepts key struct */
int dhGenk(dhKey* k);
/** given a secret (sk_mine say from dhGen above) and your friend's
 * public key (pk_yours), compute the diffie hellman value, and
 * apply a KDF to obtain buflen bytes of key, stored in keybuf */
int dhFinal(mpz_t sk_mine, mpz_t pk_mine, mpz_t pk_yours, unsigned char* keybuf, size_t buflen);
/* NOTE: pk_mine is included just to avoid recomputing it from sk_mine */
/** 3DH (as seen in Signal).  Parameters:
 * a      -- long term secret key
 * A      -- long term public key
 * x      -- ephemeral secret key
 * X      -- ephemeral public key
 * B      -- long term public key of your friend
 * Y      -- ephemeral public key of your friend
 * keybuf -- buflen bytes of key material will be written here
 * buflen -- length of keybuf
 * */
int dh3Final(mpz_t a, mpz_t A, mpz_t x, mpz_t X, mpz_t B, mpz_t Y,
		unsigned char* keybuf, size_t buflen);
/** same as dh3Final, but accepts keys instead */
int dh3Finalk(dhKey* skA, dhKey* skX, dhKey* pkB, dhKey* pkY,
		unsigned char* keybuf, size_t buflen);
#ifdef __cplusplus
}
#endif
