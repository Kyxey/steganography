#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#define MAX_MSG_SIZE 1024
#define HASH_LEN SHA256_DIGEST_LENGTH

void xor_cipher(char *data, const char *key, int len)
{
    int key_len = strlen(key);
    for (int i = 0; i < len; i++)
    {
        data[i] ^= key[i % key_len];
    }
}

void sha256(const char *data, size_t len, unsigned char *out_hash)
{
    SHA256((const unsigned char *)data, len, out_hash);
}

int embed_message(FILE *in, FILE *out, const char *msg, const char *key)
{
    fseek(in, 0, SEEK_END);
    long file_size = ftell(in);
    rewind(in);

    unsigned char *buffer = malloc(file_size);
    fread(buffer, 1, file_size, in);

    int offset = *(int *)&buffer[10];
    int msg_len = strlen(msg);
    int total_len = msg_len + HASH_LEN;

    if ((total_len + 4) * 8 > file_size - offset)
    {
        fprintf(stderr, "Message too large to embed.\n");
        free(buffer);
        return 0;
    }

    char encrypted[MAX_MSG_SIZE];
    memset(encrypted, 0, sizeof(encrypted));
    strncpy(encrypted, msg, MAX_MSG_SIZE - HASH_LEN);

    unsigned char hash[HASH_LEN];
    sha256(msg, msg_len, hash);
    memcpy(encrypted + msg_len, hash, HASH_LEN);

    xor_cipher(encrypted, key, total_len);

    for (int i = 0; i < 32; i++)
    {
        int bit = (total_len >> i) & 1;
        buffer[offset + i] = (buffer[offset + i] & ~1) | bit;
    }

    for (int i = 0; i < total_len; i++)
    {
        for (int bit = 0; bit < 8; bit++)
        {
            int value_bit = (encrypted[i] >> bit) & 1;
            buffer[offset + 32 + i * 8 + bit] = (buffer[offset + 32 + i * 8 + bit] & ~1) | value_bit;
        }
    }

    fwrite(buffer, 1, file_size, out);
    free(buffer);
    return 1;
}

int extract_message(FILE *in, const char *key)
{
    fseek(in, 0, SEEK_END);
    long file_size = ftell(in);
    rewind(in);

    unsigned char *buffer = malloc(file_size);
    fread(buffer, 1, file_size, in);

    int offset = *(int *)&buffer[10];
    int total_len = 0;

    for (int i = 0; i < 32; i++)
    {
        total_len |= (buffer[offset + i] & 1) << i;
    }

    if (total_len <= HASH_LEN || total_len > MAX_MSG_SIZE)
    {
        fprintf(stderr, "Invalid message length.\n");
        free(buffer);
        return 0;
    }

    char msg[MAX_MSG_SIZE];
    memset(msg, 0, sizeof(msg));

    for (int i = 0; i < total_len; i++)
    {
        for (int bit = 0; bit < 8; bit++)
        {
            int byte_index = offset + 32 + i * 8 + bit;
            msg[i] |= (buffer[byte_index] & 1) << bit;
        }
    }

    xor_cipher(msg, key, total_len);

    int plain_len = total_len - HASH_LEN;
    char *msg_only = msg;
    unsigned char *recv_hash = (unsigned char *)(msg + plain_len);

    unsigned char computed_hash[HASH_LEN];
    sha256(msg_only, plain_len, computed_hash);

    if (memcmp(recv_hash, computed_hash, HASH_LEN) != 0)
    {
        fprintf(stderr, "ERROR: Wrong key or corrupted data.\n");
        free(buffer);
        return 0;
    }

    msg[plain_len] = '\0';
    printf("Decrypted Message: %s\n", msg_only);

    free(buffer);
    return 1;
}

int main(int argc, char *argv[])
{
    char *method = NULL, *image_in = NULL, *image_out = NULL, *pass = NULL, *msg = NULL;

    for (int i = 1; i < argc; i++)
    {
        if ((strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "-M") == 0) && i + 1 < argc)
            method = argv[++i];
        else if ((strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "-I") == 0) && i + 1 < argc)
            image_in = argv[++i];
        else if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "-O") == 0) && i + 1 < argc)
            image_out = argv[++i];
        else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "-P") == 0) && i + 1 < argc)
            pass = argv[++i];
        else if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "-S") == 0) && i + 1 < argc)
            msg = argv[++i];
    }

    if (!method || !image_in || !pass)
    {
        fprintf(stderr, "Usage: -m encrypt|decrypt -i <image> -p <pass> [-s <message>] [-o <output image>]\n");
        return 1;
    }

    FILE *in = fopen(image_in, "rb");
    if (!in)
    {
        perror("Failed to open input image");
        return 1;
    }

    if (strcmp(method, "encrypt") == 0)
    {
        if (!msg || !image_out)
        {
            fprintf(stderr, "Encryption requires -s <message> and -o <output>\n");
            fclose(in);
            return 1;
        }
        FILE *out = fopen(image_out, "wb");
        if (!out)
        {
            perror("Failed to open output image");
            fclose(in);
            return 1;
        }

        if (embed_message(in, out, msg, pass))
            printf("Message successfully embedded into %s\n", image_out);
        else
            fprintf(stderr, "Embedding failed.\n");

        fclose(out);
    }
    else if (strcmp(method, "decrypt") == 0)
    {
        if (!extract_message(in, pass))
            fprintf(stderr, "Decryption failed.\n");
    }
    else
    {
        fprintf(stderr, "Unknown method: %s\n", method);
    }

    fclose(in);
    return 0;
}