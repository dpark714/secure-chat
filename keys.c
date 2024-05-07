#include "keys.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include "util.h"
#include <openssl/sha.h>

int initKey(dhKey* k)
{
	assert(k);
	mpz_init(k->PK);
	mpz_init(k->SK);
	/* NOTE: PK == SK == 0 at this point */
	strncpy(k->name,"default",MAX_NAME);
	return 0;
}

int shredKey(dhKey* k)
{
	assert(k);
	size_t nLimbs = mpz_size(k->SK);
	memset(mpz_limbs_write(k->SK,nLimbs),0,nLimbs*sizeof(mp_limb_t));
	mpz_clear(k->SK);
	nLimbs = mpz_size(k->PK);
	memset(mpz_limbs_write(k->PK,nLimbs),0,nLimbs*sizeof(mp_limb_t));
	mpz_clear(k->PK);
	memset(k->name,0,MAX_NAME);
	return 0;
}

/* straightforward, lazy key format:
 * name:<name...>
 * pk:<base 10 rep of A>
 * sk:<base 10 rep of a>
 * (where A = g^a)
 * */

int writeDH(char* fname, dhKey* k)
{
	assert(k);
	/* NOTE if fname was already PATH_MAX-3 or longer, the name will be
	 * cut off, and possibly we will have the public key overwrite the
	 * secret key... */
	if (strnlen(fname,PATH_MAX) > PATH_MAX-4) {
		fprintf(stderr, "no room for .pub suffix in filename %s\n",fname);
		return -2;
	}
	char fnamepub[PATH_MAX+1]; fnamepub[PATH_MAX] = 0;
	strncpy(fnamepub,fname,PATH_MAX);
	strncat(fnamepub,".pub",PATH_MAX);
	/* when saving secret key, make sure file isn't world-readable */
	int fd;
	FILE* f;
	if (mpz_cmp_ui(k->SK,0)) { /* SK present so write it */
		fd = open(fname,O_RDWR|O_CREAT|O_TRUNC,0600);
		f = fdopen(fd,"wb");
		if (!f) return -1;
		fprintf(f, "name:%s\n", k->name);
		gmp_fprintf(f, "pk:%Zd\n", k->PK);
		gmp_fprintf(f, "sk:%Zd\n", k->SK);
		fclose(f);
	}
	f = fopen(fnamepub,"wb");
	if (!f) return -1;
	fprintf(f, "name:%s\n", k->name);
	gmp_fprintf(f, "pk:%Zd\n", k->PK);
	fprintf(f, "sk:0\n");
	fclose(f);
	return 0;
}

int readDH(char* fname, dhKey* k)
{
	assert(k);
	initKey(k);
	FILE* f = fopen(fname,"rb");
	if (!f) return -1;
	int rv = 0;
	char* name;
	/* TODO %ms might not be portable?  Also might not read spaces. */
	if (fscanf(f,"name:%ms\n",&name) != 1) {
		rv = -2;
		goto end;
	}
	strncpy(k->name,name,MAX_NAME);
	k->name[MAX_NAME] = 0; /* make sure it's a c-string */
	free(name);
	if (gmp_fscanf(f,"pk:%Zd\n",k->PK) != 1) {
		rv = -2;
		goto end;
	}
	if (gmp_fscanf(f,"sk:%Zd\n",k->SK) != 1) {
		rv = -2;
		goto end;
	}
end:
	fclose(f);
	return rv;
}

char* hashPK(dhKey* k, char* hash)
{
	assert(k);
	const size_t hlen = 32; /* byte len of binary hash */
	unsigned char H[hlen]; /* buffer for binary hash */
	size_t nB;
	unsigned char* buf = Z2BYTES(NULL,&nB,k->PK);
	SHA256(buf,nB,H);
	char hc[17] = "0123456789abcdef";
	if (!hash) hash = malloc(2*hlen);
	for (size_t i = 0; i < 2*hlen; i++) {
		hash[i] = hc[((H[i/2] << 4*(i%2)) & 0xf0) >> 4];
	}
	return hash;
}
