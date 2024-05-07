#include "dh.h"
#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include "util.h"

void testDH()
{
	/* Alice: */
	NEWZ(a); /* secret key (a random exponent) */
	NEWZ(A); /* public key: A = g^a mod p */
	dhGen(a,A);
	/* Bob: */
	NEWZ(b); /* secret key (a random exponent) */
	NEWZ(B); /* public key: B = g^b mod p */
	dhGen(b,B);

	// const size_t klen = 32;
	const size_t klen = 128;
	/* Alice's key derivation: */
	unsigned char kA[klen];
	dhFinal(a,A,B,kA,klen);
	/* Bob's key derivation: */
	unsigned char kB[klen];
	dhFinal(b,B,A,kB,klen);

	/* make sure they are the same: */
	if (memcmp(kA,kB,klen) == 0) {
		printf("Alice and Bob have the same key :D\n");
	} else {
		printf("T.T\n");
	}
	printf("Alice's key:\n");
	for (size_t i = 0; i < klen; i++) {
		printf("%02x ",kA[i]);
	}
	printf("\n");
	printf("Bob's key:\n");
	for (size_t i = 0; i < klen; i++) {
		printf("%02x ",kB[i]);
	}
	printf("\n");
}

void test3DH()
{
	/* Alice's long-term key: */
	NEWZ(a); /* secret key (a random exponent) */
	NEWZ(A); /* public key: A = g^a mod p */
	dhGen(a,A);
	/* Alice's ephemeral key: */
	NEWZ(x);
	NEWZ(X);
	dhGen(x,X);
	/* Bob's long-term key: */
	NEWZ(b); /* secret key (a random exponent) */
	NEWZ(B); /* public key: B = g^b mod p */
	dhGen(b,B);
	/* Bob's ephemeral key: */
	NEWZ(y);
	NEWZ(Y);
	dhGen(y,Y);

	// const size_t klen = 32;
	const size_t klen = 128;
	/* Alice's key derivation: */
	unsigned char kA[klen];
	dh3Final(a,A,x,X,B,Y,kA,klen);
	/* Bob's key derivation: */
	unsigned char kB[klen];
	dh3Final(b,B,y,Y,A,X,kB,klen);

	/* make sure they are the same: */
	if (memcmp(kA,kB,klen) == 0) {
		printf("Alice and Bob have the same key :D\n");
	} else {
		printf("T.T\n");
	}
	printf("Alice's key:\n");
	for (size_t i = 0; i < klen; i++) {
		printf("%02x ",kA[i]);
	}
	printf("\n");
	printf("Bob's key:\n");
	for (size_t i = 0; i < klen; i++) {
		printf("%02x ",kB[i]);
	}
	printf("\n");
}

int main()
{
	/* NOTE: if for some reason you wanted to make new DH parameters,
	 * you would call initFromScratch(...) here instead */
	if (init("params") == 0) {
		// gmp_printf("Successfully read DH params:\nq = %Zd\np = %Zd\ng = %Zd\n",q,p,g);
		printf("Successfully read DH params.\n");
	}
	printf("...testing DH key exchange...\n");
	testDH();
	printf("...testing 3DH key exchange...\n");
	test3DH();
	return 0;
}
