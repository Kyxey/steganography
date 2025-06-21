#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include "headers/bmp_handler.h"
#include "headers/crypto_utils.h"

/*
 * embed_message_bmp - Hide an encrypted message inside a BMP image.
 * @infile: path to the input BMP file.
 * @outfile: path to save the output BMP file with the hidden message.
 * @msg: the message string to hide.
 * @key: the passphrase for encrypting the message.
 * Returns: 1 on success, 0 on failure.
 *
 * This function encrypts the message (with a SHA-256 hash for integrity) using AES-256-CBC,
 * then embeds the IV and ciphertext into the BMP's pixel data. It uses the LSB of each byte
 * in the pixel array to store the bits. The length of the hidden data is stored in the
 * LSB of the first 32 bytes of the pixel data.
 */
int embed_message_bmp(const char *infile, const char *outfile, const char *msg, const char *key)
{
    FILE *in = fopen(infile, "rb");
    if (!in)
        return 0;
    fseek(in, 0, SEEK_END);
    long file_size = ftell(in);
    rewind(in);

    unsigned char *buffer = malloc(file_size);
    if (!buffer)
    {
        fclose(in);
        return 0;
    }
    if (fread(buffer, 1, file_size, in) != file_size)
    {
        fclose(in);
        free(buffer);
        return 0;
    }
    fclose(in);

    // Validate BMP header
    if (file_size < 54 || buffer[0] != 'B' || buffer[1] != 'M')
    {
        free(buffer);
        return 0;
    }

    // Read BMP header fields
    unsigned int offset = (unsigned char)buffer[10] | ((unsigned char)buffer[11] << 8) |
                          ((unsigned char)buffer[12] << 16) | ((unsigned char)buffer[13] << 24);
    unsigned short bpp = (unsigned char)buffer[28] | ((unsigned char)buffer[29] << 8);
    unsigned int compression = (unsigned char)buffer[30] | ((unsigned char)buffer[31] << 8) |
                               ((unsigned char)buffer[32] << 16) | ((unsigned char)buffer[33] << 24);

    // Only 24-bit or 32-bit uncompressed BMP files are supported
    if (compression != 0 || (bpp != 24 && bpp != 32))
    {
        free(buffer);
        return 0;
    }

    // Compute SHA-256 hash of the message and prepare plaintext (message + hash)
    unsigned char hash[HASH_SIZE];
    sha256((const unsigned char *)msg, strlen(msg), hash);
    int payload_len = strlen(msg) + HASH_SIZE;
    unsigned char plaintext[MAX_MSG_SIZE];
    memcpy(plaintext, msg, strlen(msg));
    memcpy(plaintext + strlen(msg), hash, HASH_SIZE);

    // Generate random IV for encryption
    unsigned char iv[IV_SIZE];
    if (!RAND_bytes(iv, IV_SIZE))
    {
        free(buffer);
        return 0;
    }
    unsigned char ciphertext[MAX_MSG_SIZE + EVP_MAX_BLOCK_LENGTH];

    // Encrypt plaintext using AES-256-CBC with the given key
    int enc_len = aes_encrypt(plaintext, payload_len, key, ciphertext, iv);
    int total_len = IV_SIZE + enc_len;
    long cover_bytes = file_size - offset;

    // Ensure the BMP has enough space for the encrypted data
    if ((long)total_len * 8 + LENGTH_HEADER_BITS > cover_bytes)
    {
        free(buffer);
        return 0;
    }

    // Embed the length of the hidden data into the LSB of the first 32 bytes
    for (int i = 0; i < LENGTH_HEADER_BITS; i++)
    {
        int bit = (total_len >> i) & 1;
        buffer[offset + i] = (buffer[offset + i] & ~1) | bit;
    }

    // Embed the encrypted payload (IV + ciphertext) into the BMP pixel data (LSBs)
    unsigned char *combined = malloc(total_len);
    if (!combined)
    {
        free(buffer);
        return 0;
    }
    memcpy(combined, iv, IV_SIZE);
    memcpy(combined + IV_SIZE, ciphertext, enc_len);
    for (int i = 0; i < total_len; i++)
    {
        for (int bit = 0; bit < 8; bit++)
        {
            int value_bit = (combined[i] >> bit) & 1;
            buffer[offset + LENGTH_HEADER_BITS + i * 8 + bit] =
                (buffer[offset + LENGTH_HEADER_BITS + i * 8 + bit] & ~1) | value_bit;
        }
    }

    // Write the modified BMP data to the output file
    FILE *out = fopen(outfile, "wb");
    if (!out)
    {
        free(buffer);
        free(combined);
        return 0;
    }
    if (fwrite(buffer, 1, file_size, out) != file_size)
    {
        fclose(out);
        free(buffer);
        free(combined);
        return 0;
    }
    fclose(out);
    free(buffer);
    free(combined);
    return 1;
}

/*
 * extract_message_bmp - Extract a hidden message from a BMP image.
 * @infile: path to the BMP image file containing a hidden message.
 * @key: the passphrase used to encrypt the hidden message.
 * Returns: 1 if a hidden message was successfully extracted, 0 on failure.
 *
 * This function reads the 32-bit length from the LSB of the first 32 pixel bytes in the BMP data,
 * then reconstructs the hidden data bits from the remaining pixel bytes. It decrypts this data
 * and verifies the appended SHA-256 hash. If the hash matches, the original message is printed.
 */
int extract_message_bmp(const char *infile, const char *key)
{
    FILE *in = fopen(infile, "rb");
    if (!in)
        return 0;
    fseek(in, 0, SEEK_END);
    long file_size = ftell(in);
    rewind(in);

    unsigned char *buffer = malloc(file_size);
    if (!buffer)
    {
        fclose(in);
        return 0;
    }
    if (fread(buffer, 1, file_size, in) != file_size)
    {
        fclose(in);
        free(buffer);
        return 0;
    }
    fclose(in);

    // Validate BMP header
    if (file_size < 54 || buffer[0] != 'B' || buffer[1] != 'M')
    {
        free(buffer);
        return 0;
    }

    unsigned int offset = (unsigned char)buffer[10] | ((unsigned char)buffer[11] << 8) |
                          ((unsigned char)buffer[12] << 16) | ((unsigned char)buffer[13] << 24);
    unsigned short bpp = (unsigned char)buffer[28] | ((unsigned char)buffer[29] << 8);
    unsigned int compression = (unsigned char)buffer[30] | ((unsigned char)buffer[31] << 8) |
                               ((unsigned char)buffer[32] << 16) | ((unsigned char)buffer[33] << 24);

    // Only 24-bit or 32-bit uncompressed BMP files are supported
    if (compression != 0 || (bpp != 24 && bpp != 32))
    {
        free(buffer);
        return 0;
    }

    int total_len = 0;
    // Read the hidden data length from the LSB of the first 32 bytes
    for (int i = 0; i < LENGTH_HEADER_BITS; i++)
    {
        total_len |= (buffer[offset + i] & 1) << i;
    }

    // Validate length and available data
    if (total_len < IV_SIZE + HASH_SIZE || total_len > MAX_MSG_SIZE ||
        ((long)total_len * 8 + LENGTH_HEADER_BITS) > (file_size - offset))
    {
        free(buffer);
        return 0;
    }

    unsigned char *combined = malloc(total_len);
    if (!combined)
    {
        free(buffer);
        return 0;
    }
    memset(combined, 0, total_len);

    // Reconstruct the hidden data bytes bit by bit from the pixel buffer
    for (int i = 0; i < total_len; i++)
    {
        for (int bit = 0; bit < 8; bit++)
        {
            int byte_index = offset + LENGTH_HEADER_BITS + i * 8 + bit;
            combined[i] |= (buffer[byte_index] & 1) << bit;
        }
    }

    unsigned char iv[IV_SIZE];
    memcpy(iv, combined, IV_SIZE);
    unsigned char plaintext[MAX_MSG_SIZE];
    int dec_len = aes_decrypt(combined + IV_SIZE, total_len - IV_SIZE, key, plaintext, iv);
    if (dec_len <= HASH_SIZE)
    {
        free(buffer);
        free(combined);
        return 0;
    }

    // Separate the extracted hash and message
    unsigned char extracted_hash[HASH_SIZE];
    memcpy(extracted_hash, plaintext + dec_len - HASH_SIZE, HASH_SIZE);
    plaintext[dec_len - HASH_SIZE] = '\0';
    unsigned char calc_hash[HASH_SIZE];
    sha256(plaintext, dec_len - HASH_SIZE, calc_hash);

    if (memcmp(extracted_hash, calc_hash, HASH_SIZE) != 0)
    {
        // Hash mismatch: incorrect key or corrupted data
        fprintf(stderr, "Decryption failed: Incorrect key or data corrupted.\n");
        free(buffer);
        free(combined);
        return 0;
    }

    printf("Decrypted Message: %s\n", plaintext);
    free(buffer);
    free(combined);
    return 1;
}