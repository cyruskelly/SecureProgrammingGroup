#include "encrypt.h"

RSA* generate_rsa_keypair() {
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bn, NULL);
    BN_free(bn);
    return rsa;
}

void save_rsa_public_key(RSA* rsa, const char* filename) {
    FILE* fp = fopen(filename, "w");
    PEM_write_RSA_PUBKEY(fp, rsa);
    fclose(fp);
}

void save_rsa_private_key(RSA* rsa, const char* filename) {
    FILE* fp = fopen(filename, "w");
    PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
}

void encrypt_aes_gcm(const unsigned char *plaintext, int plaintext_len, 
                     unsigned char *key, unsigned char *iv, 
                     unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    EVP_CIPHER_CTX_free(ctx);
}
