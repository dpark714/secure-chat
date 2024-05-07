/* Reading/writing public and secret keys */
#pragma once
#include <gmp.h>

#define MAX_NAME 128

typedef struct {
	char name[MAX_NAME+1];
	mpz_t PK;
	mpz_t SK;
	/* NOTE: in general would want to add pointers for g,p,q,
	 * but we will likely ever only use the ones in ./params
	 * so maybe it unnecessarily complicates things. */
} dhKey;

/** initializes the integers in key *k */
int initKey(dhKey* k);
/** writes 1 or two files, depending on whether or not the secret key is
 * present in the key struct.  Using the ssh convention, the public key will be
 * in fname.pub, secret key (if available) will be in fname. */
int writeDH(char* fname, dhKey* k);
/* this will read either a public or private key, storing result in *k.
 * Public keys will have the SK field set to 0. */
int readDH(char* fname, dhKey* k);
/** zero memory for key */
int shredKey(dhKey* k);
/** Write a hash (presently SHA256, output in hex) of the public key.
 * @param *k is the key to be hashed.
 * @param hash points to a caller-allocated buffer of at least 64
 * bytes to be used as storage for the hash, or NULL.
 * @return pointer to a buffer containing the hash.  This will either
 * be the input parameter hash, or a newly allocated buffer if hash==NULL. */
char* hashPK(dhKey* k, char* hash);
