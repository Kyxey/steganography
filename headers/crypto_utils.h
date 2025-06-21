#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stddef.h> // for size_t

// Global constants for cryptography and steganography
#define MAX_MSG_SIZE 1024     // Maximum message size (bytes) for the hidden message
#define HASH_SIZE 32          // Size of SHA-256 hash in bytes
#define IV_SIZE 16            // Initialization vector (IV) size for AES (16 bytes)
#define LENGTH_HEADER_BITS 32 // Number of bits reserved for storing data length

// Function prototypes for cryptographic utilities
int sha256(const unsigned char *data, size_t len, unsigned char *out_hash);
int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const char *passkey,
                unsigned char *ciphertext, unsigned char *iv);
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, const char *passkey,
                unsigned char *plaintext, unsigned char *iv);

#endif // CRYPTO_UTILS_H