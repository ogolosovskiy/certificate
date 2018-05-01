#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
// #include "openssl\applink.c"
#include <stdio.h>
#include <string>
#include <vector>
#include <assert.h>

typedef unsigned char byte;

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

	// openssl enc - d - aes - 128 - cbc - pass env : KEY - in file.ssl - out file.txt


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


// retrurn error, 0 means sucess
// encrypts binary by password, encrypted_binary is encrypted binary 128 block
int encrypt(byte const* binary, size_t binary_len, byte const* password, size_t password_len, byte encrypted_binary[128], size_t& encrypted_binary_len)
{

	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	encrypted_binary_len = 0;
	memset(encrypted_binary, 0, sizeof(encrypted_binary));

	/* load encription alghoirithms */
	const EVP_CIPHER *cipher = 0;
	const EVP_MD *dgst = 0;
	cipher = EVP_get_cipherbyname("aes-128-cbc");
	if (!cipher) { fprintf(stderr, "no such cipher\n"); return 1; }
	dgst = EVP_get_digestbyname("md5");
	if (!dgst) { fprintf(stderr, "no such digest\n"); return 2; }


	/* create encription key from password */
	const unsigned char *salt = NULL;
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	if (!EVP_BytesToKey(cipher, dgst, salt, password, password_len, 1, key, iv))
	{
		fprintf(stderr, "EVP_BytesToKey failed\n");
		return 3;
	}

	/* encryption */
	encrypted_binary_len = encrypt_aes_128(const_cast<byte*>(binary), binary_len, key, iv, encrypted_binary);

	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();

	return 0;

}

// retrurn error, 0 means sucess
int decript(byte const* encrypted_binary, size_t encrypted_binary_len, byte const* password, size_t password_len, byte decrypted_binary[128], size_t& decripted_binary_len)
{
	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	decripted_binary_len = 0;
	memset(decrypted_binary, 0, sizeof(decrypted_binary));

	/* load encription alghoirithms */
	const EVP_CIPHER *cipher = 0;
	const EVP_MD *dgst = 0;
	cipher = EVP_get_cipherbyname("aes-128-cbc");
	if (!cipher) { fprintf(stderr, "no such cipher\n"); return 1; }
	dgst = EVP_get_digestbyname("md5");
	if (!dgst) { fprintf(stderr, "no such digest\n"); return 2; }

	/* create encription key from password */
	const unsigned char *salt = NULL;
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	if (!EVP_BytesToKey(cipher, dgst, salt, password, password_len, 1, key, iv))
	{
		fprintf(stderr, "EVP_BytesToKey failed\n");
		return 3;
	}

	/* Decription */
	decripted_binary_len = decrypt_aes_128(const_cast<byte*>(encrypted_binary), encrypted_binary_len, key, iv, decrypted_binary);
	decrypted_binary[decripted_binary_len] = 0;

	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();

	return 0;
}

int main(void)
{

	char const *plaintext = "secret+string_need_to_be_encripted";
	char const *password = "mypassword_secret";

	byte encrypted_binary[128]; // 128 because its aes-128 block
	size_t encrypted_binary_size = 0;
	int res1 = encrypt((byte const*) plaintext, strlen(plaintext), (byte const*)password, strlen(password), encrypted_binary, encrypted_binary_size);
	if (res1 != 0)
		return 1;

	std::string base64EncodeOutput;
	Base64Encode(encrypted_binary, encrypted_binary_size, base64EncodeOutput);

	printf("AES_128/Base64 token:\n%s\n", base64EncodeOutput.c_str());

	std::vector<byte> cipher_new;
	Base64Decode(base64EncodeOutput.c_str(), cipher_new);

	byte decrypted_binary[128]; // 128 because its aes-128 block
	size_t decrypted_binary_size = 0;
	int res2 = decript(cipher_new.data(), cipher_new.size(), (byte const*)password, strlen(password), decrypted_binary, decrypted_binary_size);
	if (res1 != 0)
		return 1;


/*	printf("Text/file.txt   :\n%s\n", plaintext);
	printf("\nEmulate:\nopenssl enc -aes-128-cbc -k mypassword -nosalt -p\n");
	printf("Key HEX:\n"); for (i = 0; i<cipher->key_len; ++i) { printf("%02x", key[i]); } printf("\n");
	printf("IV HEX:\n"); for (i = 0; i<cipher->iv_len; ++i) { printf("%02x", iv[i]); } printf("\n");
	printf("\nEmulate:\nopenssl enc -aes-128-cbc -pass pass:mypassword -p -nosalt -in file.txt -out file.bin\n");


	printf("\ncipher is:\n");
	BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);
	*/

	return 0;
}