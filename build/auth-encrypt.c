#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <string.h>

int auth_encrypt(unsigned char *plaintext, int plaintext_len, 
				 unsigned char *key, 
				 unsigned char *iv,
				 unsigned char *ciphertext,
				 unsigned char *tag) 
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;


	// Initialize context
	if(!(ctx = EVP_CIPHER_CTX_new()))
	    return -1;

	// Initialize encryption
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
	    return -1;

	// Initialize key and iv
	if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
	    return -1;

	// Encrypt plaintext with key and iv using the specified encryption method (aes256 gcm)
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
	    return -1;
	ciphertext_len = len;

	// Finilize encryption
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
	    return -1;
	ciphertext_len += len;

	// Get tag
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
	    return -1;

	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int auth_decrypt(unsigned char *ciphertext, int ciphertext_len,
                 unsigned char *tag,
                 unsigned char *key,
                 unsigned char *iv,
                 unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	int ret;

	// Initialize context
	if(!(ctx = EVP_CIPHER_CTX_new()))
	    return -1;

	// Initialize encryption
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
	    return -1;

	// Initialize key and iv
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
	    return -1;

	// Decrypt plaintext with key and iv using the specified encryption method (aes256 gcm)
	if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
	    return -1;
	plaintext_len = len;

	// Set tag
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
	    return -1;

	// Finilize decryption
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0) {
	    // Successful
	    plaintext_len += len;
	    return plaintext_len;
	} else {
	    return -2;
	}
}

int encrypt(char *cipher_text, unsigned char *k, unsigned char *message, long len) {
	//ENCRYPTION

	// Generate Initialization Vector
	unsigned char *iv = malloc(12);
	if (!iv) return 2;

	if (RAND_bytes(iv, 12) != 1) return 2;

	// Authenticated Encryption: Encrypt plaintext with symmetric key
	//c_msg = m encrypted with k
	unsigned char *c_msg = calloc(1, len);
	if (!c_msg) return 2;

	unsigned char *tag = malloc(16);
	if (!tag) return 2;

	int c_msg_len = auth_encrypt(message, len, k, iv, c_msg, tag);
	if (c_msg_len == -1) return 2;

	// Output result
    memcpy(cipher_text, iv, 12);
    memcpy(cipher_text + 12, tag, 16);
    memcpy(cipher_text + 28, c_msg, c_msg_len);

	free(iv);
	free(c_msg);
	free(tag);

	return 0;
}

int decrypt(char *text, unsigned char *k, char *cipher_text, long len) {
	//DECRYPTION

	// Divide message into ciphtertext, tag, and iv
	unsigned char *iv = malloc(12);
	unsigned char *tag = malloc(16);
	unsigned char *c_msg = malloc(len);
	unsigned char *msg = calloc(1, len);
	if (!iv || !tag || !c_msg || !msg) {free(tag); free(iv); free(c_msg); free(msg); return 2;}
    memcpy(iv, cipher_text, 12);
    memcpy(tag, cipher_text + 12, 16);
    memcpy(c_msg, cipher_text + 28, len);

	// Authenticated Decryption
	int msg_len = auth_decrypt(c_msg, len, tag, k, iv, msg);
	if( msg_len == -2) return 1;
	if( msg_len == -1) return 2;
	memcpy(text, msg, msg_len);
    
    free(msg);
	free(c_msg);
    free(iv);
    free(tag);

	return 0;
}