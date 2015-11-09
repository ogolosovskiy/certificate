#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "openssl\applink.c"
#include <stdio.h>
#include <string>
#include <vector>
#include <assert.h>

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

int encrypt_aes_128(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	// Cipher Block Chaining Mode(CBC)
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
		handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	* EVP_EncryptUpdate can be called multiple times if necessary
	*/
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	* this stage.
	*/
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int decrypt_aes_128(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	// Cipher Block Chaining Mode (CBC)
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
		handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	* EVP_DecryptUpdate can be called multiple times if necessary
	*/
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	* this stage.
	*/
	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) 
		handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}


size_t calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
	size_t len = strlen(b64input),
		padding = 0;

	if (b64input[len - 1] == '=' && b64input[len - 2] == '=') //last two chars are =
		padding = 2;
	else if (b64input[len - 1] == '=') //last char is =
		padding = 1;

	return (len * 3) / 4 - padding;
}

int Base64Decode(char const* b64message, std::vector<byte>& output) { //Decodes a base64 encoded string

	BIO *bio, *b64;
	unsigned char* buffer;
	size_t length;

	int decodeLen = calcDecodeLength(b64message);
	buffer = (unsigned char*)malloc(decodeLen + 1);
	buffer[decodeLen] = '\0';

	bio = BIO_new_mem_buf((char*)b64message, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	length = BIO_read(bio, buffer, strlen(b64message));
	assert(length == decodeLen); //length should equal decodeLen, else something went horribly wrong
	BIO_free_all(bio);

	output = std::vector<byte>(length);
	memcpy(output.data(), buffer, length);

	free(buffer);

	return (0); //success
}

int Base64Encode(const unsigned char* buffer, size_t length, std::string& output) { //Encodes a binary safe base 64 string
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	output = std::string(bufferPtr->data, bufferPtr->length);
	BUF_MEM_free(bufferPtr);
	return (0); //success
}

int main(void)
{
	/* Set up the key and iv. Do I need to say to not hard code these in a
	* real application? :-)
	*/

	/* A 256 bit key */
	unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
	printf("secret key %s\n", key);


	/* Message to be encrypted */
	unsigned char *plaintext =
		(unsigned char *)  "{_40_BYTES_SEQ_XXXXXXXXXXXXXXXXXXXXXXXXXX|_6_BYT|1446821786}";
	printf("server_token %s\n", plaintext);
	printf("server_token size %d\n", strlen((const char*)plaintext));

	/* Buffer for ciphertext. Ensure the buffer is long enough for the
	* ciphertext which may be longer than the plaintext, dependant on the
	* algorithm and mode
	*/
	unsigned char ciphertext[128];

	/* Buffer for the decrypted text */
	unsigned char decryptedtext[128];

	int decryptedtext_len, ciphertext_len;

	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	/* Encrypt the plaintext */
	ciphertext_len = encrypt_aes_128(plaintext, strlen((char *)plaintext), key, 0,
		ciphertext);

	/* Do something useful with the ciphertext here */
//	printf("Ciphertext is:\n");
//	BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

	// base64 it
	std::string base64EncodeOutput;
	// to do check out
	Base64Encode(ciphertext, ciphertext_len, base64EncodeOutput);

	printf("AES_128/Base64 server_token %s\n", base64EncodeOutput.c_str());
	printf("AES_128/Base64 server_token size %d\n", base64EncodeOutput.size());


	std::vector<byte> cipher_new;
	Base64Decode(base64EncodeOutput.c_str(), cipher_new);

	/* Decrypt the ciphertext */
	//unsigned char *key1 = (unsigned char *)"11234567890123456789012345678901";
	decryptedtext_len = decrypt_aes_128(cipher_new.data(), cipher_new.size(), key, 0,
		decryptedtext);

	/* Add a NULL terminator. We are expecting printable text */
	decryptedtext[decryptedtext_len] = '\0';

	/* Show the decrypted text */
	printf("Decrypted text is:\n");
	printf("%s\n", decryptedtext);

	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();

	return 0;
}