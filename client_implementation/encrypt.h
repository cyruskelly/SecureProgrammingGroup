#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <openssl/rsa.h>

RSA* generate_rsa_keypair();
void save_rsa_public_key(RSA* rsa, const char* filename);
void save_rsa_private_key(RSA* rsa, const char* filename);

void encrypt_aes_gcm(const unsigned char *plaintext, int plaintext_len,
                     unsigned char *key, unsigned char *iv,
                     unsigned char *ciphertext, unsigned char *tag);

#endif
