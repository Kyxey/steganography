#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define MAX_MSG_SIZE 1024
#define HASH_SIZE 32
#define IV_SIZE 16
#define HEADER_OFFSET_POS 10
#define LENGTH_HEADER_BITS 32

void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int sha256(const unsigned char *data, size_t len, unsigned char *out_hash)
{
    return SHA256(data, len, out_hash) != NULL;
}

int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const char *passkey, unsigned char *ciphertext, unsigned char *iv)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char key[32];
    int len, ciphertext_len;

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    EVP_BytesToKey(cipher, EVP_sha256(), NULL, (unsigned char *)passkey, strlen(passkey), 1, key, iv);

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, const char *passkey, unsigned char *plaintext, unsigned char *iv)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char key[32];
    int len, plaintext_len;

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    EVP_BytesToKey(cipher, EVP_sha256(), NULL, (unsigned char *)passkey, strlen(passkey), 1, key, iv);

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

int embed_message(FILE *in, FILE *out, const char *msg, const char *key)
{
    fseek(in, 0, SEEK_END);
    long filesize = ftell(in);
    rewind(in);

    unsigned char *buffer = malloc(filesize);
    if (!buffer || fread(buffer, 1, filesize, in) != filesize)
        return 0;

    int offset = *(int *)&buffer[HEADER_OFFSET_POS];

    unsigned char hash[HASH_SIZE];
    sha256((const unsigned char *)msg, strlen(msg), hash);

    int payload_len = strlen(msg) + HASH_SIZE;
    unsigned char plaintext[MAX_MSG_SIZE];
    memcpy(plaintext, msg, strlen(msg));
    memcpy(plaintext + strlen(msg), hash, HASH_SIZE);

    unsigned char iv[IV_SIZE];
    if (!RAND_bytes(iv, IV_SIZE))
        return 0;

    unsigned char ciphertext[MAX_MSG_SIZE + EVP_MAX_BLOCK_LENGTH];
    int enc_len = aes_encrypt(plaintext, payload_len, key, ciphertext, iv);

    int total_len = IV_SIZE + enc_len;
    if ((total_len * 8 + LENGTH_HEADER_BITS) > (filesize - offset))
        return 0;

    int i;
    for (i = 0; i < LENGTH_HEADER_BITS; i++)
    {
        buffer[offset + i] = (buffer[offset + i] & ~1) | ((total_len >> i) & 1);
    }

    unsigned char *combined = malloc(total_len);
    memcpy(combined, iv, IV_SIZE);
    memcpy(combined + IV_SIZE, ciphertext, enc_len);

    for (i = 0; i < total_len * 8; i++)
    {
        int byte_index = i / 8;
        int bit_index = i % 8;
        buffer[offset + LENGTH_HEADER_BITS + i] =
            (buffer[offset + LENGTH_HEADER_BITS + i] & ~1) |
            ((combined[byte_index] >> bit_index) & 1);
    }

    fwrite(buffer, 1, filesize, out);
    free(buffer);
    free(combined);
    return 1;
}

int extract_message(FILE *in, const char *key)
{
    fseek(in, 0, SEEK_END);
    long filesize = ftell(in);
    rewind(in);

    unsigned char *buffer = malloc(filesize);
    if (!buffer || fread(buffer, 1, filesize, in) != filesize)
        return 0;

    int offset = *(int *)&buffer[HEADER_OFFSET_POS];
    int total_len = 0;

    for (int i = 0; i < LENGTH_HEADER_BITS; i++)
    {
        total_len |= (buffer[offset + i] & 1) << i;
    }

    if (total_len < IV_SIZE + HASH_SIZE || total_len > MAX_MSG_SIZE)
        return 0;

    unsigned char *combined = malloc(total_len);
    for (int i = 0; i < total_len * 8; i++)
    {
        int byte_index = i / 8;
        int bit_index = i % 8;
        combined[byte_index] &= ~(1 << bit_index);
        combined[byte_index] |= (buffer[offset + LENGTH_HEADER_BITS + i] & 1) << bit_index;
    }

    unsigned char iv[IV_SIZE];
    memcpy(iv, combined, IV_SIZE);

    unsigned char plaintext[MAX_MSG_SIZE];
    int dec_len = aes_decrypt(combined + IV_SIZE, total_len - IV_SIZE, key, plaintext, iv);
    if (dec_len <= HASH_SIZE)
        return 0;

    unsigned char extracted_hash[HASH_SIZE];
    memcpy(extracted_hash, plaintext + dec_len - HASH_SIZE, HASH_SIZE);
    plaintext[dec_len - HASH_SIZE] = '\0';

    unsigned char calc_hash[HASH_SIZE];
    sha256(plaintext, dec_len - HASH_SIZE, calc_hash);

    if (memcmp(extracted_hash, calc_hash, HASH_SIZE) != 0)
    {
        fprintf(stderr, "Decryption failed: Incorrect key or data corrupted.\n");
        return 0;
    }

    printf("Decrypted Message: %s\n", plaintext);
    free(buffer);
    free(combined);
    return 1;
}

int main(int argc, char *argv[])
{
    char *method = NULL, *input_file = NULL, *output_file = NULL, *passkey = NULL, *message = NULL;
    for (int i = 1; i < argc; i++)
    {
        if ((strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "-M") == 0) && i + 1 < argc)
            method = argv[++i];
        else if ((strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "-I") == 0) && i + 1 < argc)
            input_file = argv[++i];
        else if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "-O") == 0) && i + 1 < argc)
            output_file = argv[++i];
        else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "-P") == 0) && i + 1 < argc)
            passkey = argv[++i];
        else if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "-S") == 0) && i + 1 < argc)
            message = argv[++i];
    }

    if (!method || !input_file || !passkey)
    {
        fprintf(stderr, "Usage: %s -m <method> -i <input.bmp> -p <passkey> [-s <message>] [-o <output.bmp>]\n", argv[0]);
        return 1;
    }

    FILE *in = fopen(input_file, "rb");
    if (!in)
    {
        perror("Failed to open input file");
        return 1;
    }

    if (strcasecmp(method, "encrypt") == 0)
    {
        if (!message || !output_file)
        {
            fprintf(stderr, "Encryption requires -s <message> and -o <output.bmp>\n");
            fclose(in);
            return 1;
        }
        FILE *out = fopen(output_file, "wb");
        if (!out)
        {
            perror("Failed to open output file");
            fclose(in);
            return 1;
        }
        if (embed_message(in, out, message, passkey))
            printf("Message successfully embedded into image.\n");
        else
            fprintf(stderr, "Failed to embed message.\n");
        fclose(out);
    }
    else if (strcasecmp(method, "decrypt") == 0)
    {
        if (!extract_message(in, passkey))
            fprintf(stderr, "Failed to extract message.\n");
    }
    else
    {
        fprintf(stderr, "Unknown method: %s\n", method);
    }

    fclose(in);
    return 0;
}