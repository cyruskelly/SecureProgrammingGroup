#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <string.h>

EVP_PKEY* generate_rsa_keypair();
void save_rsa_public_key(EVP_PKEY* pkey, const char* filename);
void save_rsa_private_key(EVP_PKEY* pkey, const char* filename);

void encrypt_aes_gcm(const unsigned char *plaintext, int plaintext_len,
                     unsigned char *key, unsigned char *iv,
                     unsigned char *ciphertext, unsigned char *tag);

#endif
