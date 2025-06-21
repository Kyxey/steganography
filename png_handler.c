#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <openssl/rand.h>
#include <png.h>
#include "headers/png_handler.h"
#include "headers/crypto_utils.h"

/*
 * embed_message_png - Hide an encrypted message inside a PNG image.
 * @infile: path to the input PNG image file.
 * @outfile: path to save the output PNG image with the hidden message.
 * @msg: the null-terminated message string to hide.
 * @key: the passphrase for encrypting the message.
 * Returns: 1 on success, 0 on failure.
 *
 * This function encrypts the given message (appending a SHA-256 hash for integrity) using AES-256-CBC.
 * The resulting IV and ciphertext are then embedded into the least significant bits of the image's pixel data.
 * The length of the hidden data (IV + ciphertext) is stored in the first LENGTH_HEADER_BITS (32) pixel LSBs.
 */
int embed_message_png(const char *infile, const char *outfile, const char *msg, const char *key)
{
    FILE *fp = fopen(infile, "rb");
    if (!fp)
        return 0;

    png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    png_infop info = png_create_info_struct(png);
    if (setjmp(png_jmpbuf(png)))
    {
        fclose(fp);
        return 0;
    }
    png_init_io(png, fp);
    png_read_info(png, info);

    int width = png_get_image_width(png, info);
    int height = png_get_image_height(png, info);
    png_byte color_type = png_get_color_type(png, info);
    png_byte bit_depth = png_get_bit_depth(png, info);

    // Normalize PNG to 8-bit RGBA (handle various color types and bit depths)
    if (bit_depth == 16)
        png_set_strip_16(png);
    if (color_type == PNG_COLOR_TYPE_PALETTE)
        png_set_palette_to_rgb(png);
    if (color_type == PNG_COLOR_TYPE_GRAY && bit_depth < 8)
        png_set_expand_gray_1_2_4_to_8(png);
    if (png_get_valid(png, info, PNG_INFO_tRNS))
        png_set_tRNS_to_alpha(png);
    if (color_type == PNG_COLOR_TYPE_RGB || color_type == PNG_COLOR_TYPE_GRAY)
        png_set_filler(png, 0xFF, PNG_FILLER_AFTER);
    if (color_type == PNG_COLOR_TYPE_GRAY || color_type == PNG_COLOR_TYPE_GRAY_ALPHA)
        png_set_gray_to_rgb(png);

    png_read_update_info(png, info);

    // Allocate memory for image rows
    png_bytep *rows = malloc(sizeof(png_bytep) * height);
    for (int y = 0; y < height; y++)
        rows[y] = malloc(png_get_rowbytes(png, info));
    png_read_image(png, rows);
    fclose(fp);

    // Compute SHA-256 hash of the message (for integrity checking)
    unsigned char hash[HASH_SIZE];
    sha256((const unsigned char *)msg, strlen(msg), hash);
    int payload_len = strlen(msg) + HASH_SIZE;
    unsigned char plaintext[MAX_MSG_SIZE];

    // Copy message and its hash into plaintext buffer
    memcpy(plaintext, msg, strlen(msg));
    memcpy(plaintext + strlen(msg), hash, HASH_SIZE);

    // Generate a random IV for AES encryption
    unsigned char iv[IV_SIZE];
    if (!RAND_bytes(iv, IV_SIZE))
    {
        // Cleanup and return failure
        for (int y = 0; y < height; y++)
            free(rows[y]);
        free(rows);
        return 0;
    }

    unsigned char ciphertext[MAX_MSG_SIZE + EVP_MAX_BLOCK_LENGTH];
    // Encrypt the plaintext (message + hash) using the given passphrase
    int enc_len = aes_encrypt(plaintext, payload_len, key, ciphertext, iv);
    int total_len = IV_SIZE + enc_len;

    // Ensure the image can accommodate the encrypted data (length + data bits)
    if ((total_len * 8 + LENGTH_HEADER_BITS) > (width * height * 3))
    {
        for (int y = 0; y < height; y++)
            free(rows[y]);
        free(rows);
        return 0;
    }

    // Embed the length of the hidden data into the first 32 pixel LSBs (RGB channels only)
    for (int i = 0; i < LENGTH_HEADER_BITS; i++)
    {
        int idx = i;
        int row = idx / (width * 3);
        int col = (idx / 3) % width;
        int ch = idx % 3;
        rows[row][col * 4 + ch] = (rows[row][col * 4 + ch] & ~1) | ((total_len >> i) & 1);
    }

    // Combine IV and ciphertext into one buffer
    unsigned char *combined = malloc(total_len);
    memcpy(combined, iv, IV_SIZE);
    memcpy(combined + IV_SIZE, ciphertext, enc_len);

    // Embed the encrypted payload (IV + ciphertext) bit-by-bit into the image pixels
    for (int i = 0; i < total_len * 8; i++)
    {
        int idx = i + LENGTH_HEADER_BITS;
        int row = idx / (width * 3);
        int col = (idx / 3) % width;
        int ch = idx % 3;
        rows[row][col * 4 + ch] = (rows[row][col * 4 + ch] & ~1) | ((combined[i / 8] >> (i % 8)) & 1);
    }

    // Write the modified image to the output PNG file
    FILE *out = fopen(outfile, "wb");
    png_structp write_png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    png_infop write_info = png_create_info_struct(write_png);
    if (setjmp(png_jmpbuf(write_png)))
    {
        // Cleanup on failure
        fclose(out);
        for (int y = 0; y < height; y++)
            free(rows[y]);
        free(rows);
        free(combined);
        return 0;
    }
    png_init_io(write_png, out);
    png_set_IHDR(write_png, write_info, width, height, 8, PNG_COLOR_TYPE_RGBA,
                 PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
    png_write_info(write_png, write_info);
    png_write_image(write_png, rows);
    png_write_end(write_png, NULL);
    fclose(out);

    // Free allocated memory
    for (int y = 0; y < height; y++)
        free(rows[y]);
    free(rows);
    free(combined);
    return 1;
}

/*
 * extract_message_png - Extract a hidden message from a PNG image.
 * @infile: path to the PNG image file containing a hidden message.
 * @key: the passphrase used to encrypt the hidden message.
 * Returns: 1 if a hidden message was successfully extracted, 0 on failure.
 *
 * This function reads the 32-bit length from the image's pixel LSBs, then extracts that many bytes of hidden data from
 * the pixel array. It decrypts the data with the given key and verifies the SHA-256 hash appended to the message.
 * If the hash is correct, the decrypted message is printed to stdout.
 */
int extract_message_png(const char *infile, const char *key)
{
    FILE *fp = fopen(infile, "rb");
    if (!fp)
        return 0;

    png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    png_infop info = png_create_info_struct(png);
    if (setjmp(png_jmpbuf(png)))
    {
        fclose(fp);
        return 0;
    }
    png_init_io(png, fp);
    png_read_info(png, info);

    int width = png_get_image_width(png, info);
    int height = png_get_image_height(png, info);
    png_byte color_type = png_get_color_type(png, info);
    png_byte bit_depth = png_get_bit_depth(png, info);

    // Prepare PNG image data to 8-bit RGBA format (same conversions as embedding)
    if (bit_depth == 16)
        png_set_strip_16(png);
    if (color_type == PNG_COLOR_TYPE_PALETTE)
        png_set_palette_to_rgb(png);
    if (color_type == PNG_COLOR_TYPE_GRAY && bit_depth < 8)
        png_set_expand_gray_1_2_4_to_8(png);
    if (png_get_valid(png, info, PNG_INFO_tRNS))
        png_set_tRNS_to_alpha(png);
    if (color_type == PNG_COLOR_TYPE_RGB || color_type == PNG_COLOR_TYPE_GRAY)
        png_set_filler(png, 0xFF, PNG_FILLER_AFTER);
    if (color_type == PNG_COLOR_TYPE_GRAY || color_type == PNG_COLOR_TYPE_GRAY_ALPHA)
        png_set_gray_to_rgb(png);

    png_read_update_info(png, info);

    // Allocate memory for image rows
    png_bytep *rows = malloc(sizeof(png_bytep) * height);
    for (int y = 0; y < height; y++)
        rows[y] = malloc(png_get_rowbytes(png, info));
    png_read_image(png, rows);
    fclose(fp);

    int total_len = 0;
    // Read 32-bit length header from LSBs (RGB channels only)
    for (int i = 0; i < LENGTH_HEADER_BITS; i++)
    {
        int idx = i;
        int row = idx / (width * 3);
        int col = (idx / 3) % width;
        int ch = idx % 3;
        total_len |= (rows[row][col * 4 + ch] & 1) << i;
    }

    if (total_len < IV_SIZE + HASH_SIZE || total_len > MAX_MSG_SIZE)
    {
        // Not a valid hidden data length
        for (int y = 0; y < height; y++)
            free(rows[y]);
        free(rows);
        return 0;
    }

    unsigned char *combined = malloc(total_len);
    // Extract hidden data bits into combined buffer
    for (int i = 0; i < total_len * 8; i++)
    {
        int idx = i + LENGTH_HEADER_BITS;
        int row = idx / (width * 3);
        int col = (idx / 3) % width;
        int ch = idx % 3;
        combined[i / 8] &= ~(1 << (i % 8));
        combined[i / 8] |= (rows[row][col * 4 + ch] & 1) << (i % 8);
    }

    unsigned char iv[IV_SIZE];
    memcpy(iv, combined, IV_SIZE);
    unsigned char plaintext[MAX_MSG_SIZE];
    int dec_len = aes_decrypt(combined + IV_SIZE, total_len - IV_SIZE, key, plaintext, iv);
    if (dec_len <= HASH_SIZE)
    {
        for (int y = 0; y < height; y++)
            free(rows[y]);
        free(rows);
        free(combined);
        return 0;
    }

    // Separate the extracted hash from the plaintext
    unsigned char extracted_hash[HASH_SIZE];
    memcpy(extracted_hash, plaintext + dec_len - HASH_SIZE, HASH_SIZE);
    plaintext[dec_len - HASH_SIZE] = '\0';
    unsigned char calc_hash[HASH_SIZE];
    sha256(plaintext, dec_len - HASH_SIZE, calc_hash);

    if (memcmp(extracted_hash, calc_hash, HASH_SIZE) != 0)
    {
        // Hash mismatch: incorrect key or corrupted image data
        fprintf(stderr, "Decryption failed: Incorrect key or data corrupted.\n");
        for (int y = 0; y < height; y++)
            free(rows[y]);
        free(rows);
        free(combined);
        return 0;
    }

    printf("Decrypted Message: %s\n", plaintext);
    for (int y = 0; y < height; y++)
        free(rows[y]);
    free(rows);
    free(combined);
    return 1;
}