/* examples of using various crypto utilities from openssl. */
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

/* demonstrates hashing (SHA family) */
void sha_example()
{
	/* hash a string with sha256 */
	char* message = "this is a test message :D";
	unsigned char hash[32]; /* change 32 to 64 if you use sha512 */
	SHA256((unsigned char*)message,strlen(message),hash);
	for (size_t i = 0; i < 32; i++) {
		printf("%02x",hash[i]);
	}
	printf("\n");
	/* you can check that this is correct by running
	 * $ echo -n 'this is a test message :D' | sha256sum */
}

/* demonstrates HMAC */
void hmac_example()
{
	char* hmackey = "asdfasdfasdfasdfasdfasdf";
	unsigned char mac[64]; /* if using sha512 */
	memset(mac,0,64);
	char* message = "this is a test message :D";
	HMAC(EVP_sha512(),hmackey,strlen(hmackey),(unsigned char*)message,
			strlen(message),mac,0);
	printf("hmac-512(\"%s\"):\n",message);
	for (size_t i = 0; i < 64; i++) {
		printf("%02x",mac[i]);
	}
	printf("\n");
}

/* demonstrates AES in counter mode */
void ctr_example()
{
	unsigned char key[32];
	size_t i;
	/* setup dummy (non-random) key and IV */
	for (i = 0; i < 32; i++) key[i] = i;
	unsigned char iv[16];
	for (i = 0; i < 16; i++) iv[i] = i;
	/* NOTE: in general you need t compute the sizes of these
	 * buffers.  512 is an arbitrary value larger than what we
	 * will need for our short message. */
	unsigned char ct[512];
	unsigned char pt[512];
	/* so you can see which bytes were written: */
	memset(ct,0,512);
	memset(pt,0,512);
	char* message = "this is a test message :D";
	size_t len = strlen(message);
	/* encrypt: */
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_EncryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
		ERR_print_errors_fp(stderr);
	int nWritten; /* stores number of written bytes (size of ciphertext) */
	if (1!=EVP_EncryptUpdate(ctx,ct,&nWritten,(unsigned char*)message,len))
		ERR_print_errors_fp(stderr);
	EVP_CIPHER_CTX_free(ctx);
	size_t ctlen = nWritten;
	printf("ciphertext of length %i:\n",nWritten);
	for (i = 0; i < ctlen; i++) {
		printf("%02x",ct[i]);
	}
	printf("\n");
	/* NOTE: the context (ctx) keeps track of the updated counter/IV for
	 * you which is nice when sending sequences of messages, as in the chat
	 * program (this way you don't have to generate and send a fresh IV for
	 * each message). */

	/* now decrypt.  NOTE: in counter mode, encryption and decryption are
	 * actually identical, so doing the above again would work.  Also
	 * note that it is crucial to make sure IVs are not reused.  */
	/* wipe out plaintext to be sure it worked: */
	memset(pt,0,512);
	ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
		ERR_print_errors_fp(stderr);
	#if 0
	if (1!=EVP_DecryptUpdate(ctx,pt,&nWritten,ct,ctlen))
		ERR_print_errors_fp(stderr);
	printf("decrypted %i bytes:\n%s\n",nWritten,pt);
	#endif
	for (size_t i = 0; i < len; i++) {
		if (1!=EVP_DecryptUpdate(ctx,pt+i,&nWritten,ct+i,1))
			ERR_print_errors_fp(stderr);
	}
	printf("decrypted %lu bytes:\n%s\n",len,pt);
	EVP_CIPHER_CTX_free(ctx);
	/* NOTE: counter mode will preserve the length (although the person
	 * decrypting needs to know the IV) */
}

/* demonstrate RSA keygen,enc,dec */
#if 0
void rsa_example()
{
	/* first generate a key */
	RSA* keys = RSA_new();
	if (!keys) exit(1);
	BIGNUM* e = BN_new();
	if (!e) exit(1);
	BN_set_word(e,RSA_F4); /* e = 65537  */
	/* NOTE: if you have an old enough openssl library, you might
	 * have to setup the random number generator before this call: */
	int r = RSA_generate_key_ex(keys,2048,e,NULL);
	if (r != 1) exit(1);
	PEM_write_RSA_PUBKEY(stdout,keys);
	/* NOTE: you could fill in the last 5 parameters if you wanted to
	 * password protect the private key. */
	PEM_write_RSAPrivateKey(stdout,keys,NULL,NULL,0,NULL,NULL);
	char* message = "this is a test message :D";
	size_t len = strlen(message);
	unsigned char* ct = malloc(RSA_size(keys));
	int ctlen = RSA_public_encrypt(len+1 /* include null char */, (unsigned char*)message,
			ct, keys, RSA_PKCS1_OAEP_PADDING);
	if (ctlen == -1) exit(1);
	/* print RSA ciphertext */
	printf("RSA ciphertext:\n");
	for (int i = 0; i < ctlen; i++) printf("%02x",ct[i]);
	printf("\n");
	/* now try to decrypt */
	char* pt = malloc(ctlen);
	size_t ptlen = RSA_private_decrypt(ctlen,ct,(unsigned char*)pt,keys,RSA_PKCS1_OAEP_PADDING);
	if (ptlen == -1) exit(1);
	printf("RSA decrypted plaintext:\n%s\n",pt);
}
#endif

/* TODO: add signature example  */

int main()
{
	// rsa_example();
	printf("~~~~~~~~~~~~~~~~~~~~~~~\n");
	ctr_example();
	printf("~~~~~~~~~~~~~~~~~~~~~~~\n");
	sha_example();
	printf("~~~~~~~~~~~~~~~~~~~~~~~\n");
	hmac_example();
	return 0;
}
