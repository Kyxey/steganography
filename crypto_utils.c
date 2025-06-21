#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include "headers/crypto_utils.h"

/*
 * handleErrors - Print OpenSSL error messages to stderr and abort the program.
 */
void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

/*
 * sha256 - Compute SHA-256 hash of the given data buffer.
 * @data: pointer to the input data buffer.
 * @len: length of the data in bytes.
 * @out_hash: output buffer (32 bytes) to store the hash.
 * Returns: 1 on success (hash is stored in out_hash), 0 on failure.
 */
int sha256(const unsigned char *data, size_t len, unsigned char *out_hash)
{
    return SHA256(data, len, out_hash) != NULL;
}

/*
 * aes_encrypt - Encrypt a plaintext buffer using AES-256-CBC.
 * @plaintext: pointer to the data to encrypt.
 * @plaintext_len: length of the plaintext in bytes.
 * @passkey: null-terminated passphrase used to derive the encryption key.
 * @ciphertext: output buffer to store the encrypted data.
 * @iv: output buffer to store the generated IV (16 bytes).
 * Returns: number of bytes written to ciphertext (ciphertext length).
 *
 * Note: The key and IV are derived from the passkey using a SHA-256 based KDF (EVP_BytesToKey).
 */
int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const char *passkey,
                unsigned char *ciphertext, unsigned char *iv)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char key[32];
    int len, ciphertext_len;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();

    // Derive key and IV from passphrase
    EVP_BytesToKey(cipher, EVP_sha256(), NULL,
                   (unsigned char *)passkey, strlen(passkey), 1, key, iv);

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/*
 * aes_decrypt - Decrypt data using AES-256-CBC.
 * @ciphertext: pointer to the encrypted data buffer.
 * @ciphertext_len: length of the ciphertext in bytes.
 * @passkey: passphrase used to derive the decryption key (must match encryption passkey).
 * @plaintext: output buffer to store the decrypted plaintext.
 * @iv: initialization vector used for decryption (16 bytes).
 * Returns: number of bytes in the decrypted plaintext, or -1 if decryption fails.
 */
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, const char *passkey,
                unsigned char *plaintext, unsigned char *iv)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char key[32];
    int len, plaintext_len;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();

    // Derive key and IV from passphrase
    EVP_BytesToKey(cipher, EVP_sha256(), NULL,
                   (unsigned char *)passkey, strlen(passkey), 1, key, iv);

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1; // decryption failed
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}