#include "encrypt.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>

// Generate an RSA key pair using the EVP_PKEY API
EVP_PKEY* generate_rsa_keypair() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (!ctx) {
        fprintf(stderr, "Error creating EVP_PKEY context\n");
        return nullptr;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Error initializing keygen\n");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        fprintf(stderr, "Error setting RSA keygen bits\n");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Error generating RSA key\n");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// Save the RSA public key to a file
void save_rsa_public_key(EVP_PKEY* pkey, const char* filename) {
    BIO* bio = BIO_new_file(filename, "w");
    if (!bio) {
        fprintf(stderr, "Error opening file for writing public key\n");
        return;
    }
    PEM_write_bio_PUBKEY(bio, pkey);
    BIO_free(bio);
}

// Save the RSA private key to a file
void save_rsa_private_key(EVP_PKEY* pkey, const char* filename) {
    BIO* bio = BIO_new_file(filename, "w");
    if (!bio) {
        fprintf(stderr, "Error opening file for writing private key\n");
        return;
    }
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    BIO_free(bio);
}

// Encrypt data using AES-GCM
void encrypt_aes_gcm(const unsigned char* plaintext, int plaintext_len,
                     unsigned char* key, unsigned char* iv,
                     unsigned char* ciphertext, unsigned char* tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating EVP_CIPHER_CTX\n");
        return;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "Error initializing AES-GCM encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        fprintf(stderr, "Error setting key and IV for AES-GCM encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        fprintf(stderr, "Error during AES-GCM encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        fprintf(stderr, "Error finalizing AES-GCM encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        fprintf(stderr, "Error getting AES-GCM authentication tag\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    EVP_CIPHER_CTX_free(ctx);
}
