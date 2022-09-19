/*
 * The Bank takes commands from the ATM, handled by
 * bank_process_remote_command.
 *
 * You can add more functions as needed.
 */

#ifndef __AUTH_ENCRYPT_H__
#define __AUTH_ENCRYPT_H__

#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <string.h>


int auth_encrypt(unsigned char *plaintext, int plaintext_len, 
				 unsigned char *key, 
				 unsigned char *iv,
				 unsigned char *ciphertext,
				 unsigned char *tag);
int auth_decrypt(unsigned char *ciphertext, int ciphertext_len,
                 unsigned char *tag,
                 unsigned char *key,
                 unsigned char *iv,
                 unsigned char *plaintext);
int encrypt(char *cipher_text, unsigned char *k, unsigned char *message, long len);
int decrypt(char *text, unsigned char *k, char *cipher_text, long len);

#endif

