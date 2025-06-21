#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <png.h>
#include <jpeglib.h>
#include <jerror.h>

#define MAX_MSG_SIZE 1024       // Maximum message size (in bytes) for the hidden message
#define HASH_SIZE 32            // Size of SHA-256 hash in bytes
#define IV_SIZE 16              // Initialization vector (IV) size for AES (16 bytes)
#define LENGTH_HEADER_BITS 32   // Number of bits reserved for storing data length
#define JPEG_MARKER_ID 0xE1     // JPEG APP1 marker code used for steganography
#define JPEG_MARKER_TAG "STEGO" // Tag to identify custom JPEG marker containing hidden data

/*
 * get_file_ext - Extract the file extension from a filename string.
 * @filename: input file name string.
 * Returns: pointer to the extension substring (after the last '.'),
 *          or an empty string if no extension is found.
 */
const char *get_file_ext(const char *filename)
{
    const char *dot = strrchr(filename, '.');
    return (!dot || dot == filename) ? "" : dot + 1;
}

/*
 * handleErrors - Print OpenSSL error messages to stderr and abort the program.
 * (No parameters.)
 * Returns: This function does not return (it terminates the program).
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

/*
 * aes_decrypt - Decrypt data using AES-256-CBC.
 * @ciphertext: pointer to the encrypted data buffer.
 * @ciphertext_len: length of the ciphertext in bytes.
 * @passkey: passphrase used to derive the decryption key (must match encryption passkey).
 * @plaintext: output buffer to store the decrypted plaintext.
 * @iv: initialization vector used for decryption (16 bytes).
 * Returns: number of bytes in the decrypted plaintext, or -1 if decryption fails.
 */
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
        return 0;
    png_init_io(png, fp);
    png_read_info(png, info);

    int width = png_get_image_width(png, info);
    int height = png_get_image_height(png, info);
    png_byte color_type = png_get_color_type(png, info);
    png_byte bit_depth = png_get_bit_depth(png, info);

    // Normalize PNG to 8-bit RGBA (strip 16-bit, expand palette/gray, add full alpha)
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

    // Copy message and its hash into a plaintext buffer
    memcpy(plaintext, msg, strlen(msg));
    memcpy(plaintext + strlen(msg), hash, HASH_SIZE);

    // Generate a random IV for AES encryption
    unsigned char iv[IV_SIZE];
    if (!RAND_bytes(iv, IV_SIZE))
        return 0;

    unsigned char ciphertext[MAX_MSG_SIZE + EVP_MAX_BLOCK_LENGTH];

    // Encrypt the plaintext (message+hash) using the given passphrase
    int enc_len = aes_encrypt(plaintext, payload_len, key, ciphertext, iv);

    int total_len = IV_SIZE + enc_len;

    // Ensure the image can accommodate the encrypted data (length + data bits)
    if ((total_len * 8 + LENGTH_HEADER_BITS) > (width * height * 3))
        return 0;

    // Embed the length of the hidden data into the first 32 pixel LSBs
    // Only uses RGB channels of pixels (alpha channel is not modified)
    for (int i = 0; i < LENGTH_HEADER_BITS; i++)
    {
        int idx = i;
        int row = idx / (width * 3);
        int col = (idx / 3) % width;
        int ch = idx % 3;
        rows[row][col * 4 + ch] = (rows[row][col * 4 + ch] & ~1) | ((total_len >> i) & 1);
    }

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

    FILE *out = fopen(outfile, "wb");
    png_structp write_png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    png_infop write_info = png_create_info_struct(write_png);
    if (setjmp(png_jmpbuf(write_png)))
        return 0;
    png_init_io(write_png, out);
    png_set_IHDR(write_png, write_info, width, height, 8, PNG_COLOR_TYPE_RGBA, PNG_INTERLACE_NONE,
                 PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
    png_write_info(write_png, write_info);
    png_write_image(write_png, rows);
    png_write_end(write_png, NULL);
    fclose(out);

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
        return 0;
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
    png_bytep *rows = malloc(sizeof(png_bytep) * height);
    for (int y = 0; y < height; y++)
        rows[y] = malloc(png_get_rowbytes(png, info));
    png_read_image(png, rows);
    fclose(fp);

    int total_len = 0;

    // Read 32-bit length header from LSBs
    // (Only RGB channels are used for embedding; alpha channel is unchanged)
    for (int i = 0; i < LENGTH_HEADER_BITS; i++)
    {
        int idx = i;
        int row = idx / (width * 3);
        int col = (idx / 3) % width;
        int ch = idx % 3;
        total_len |= (rows[row][col * 4 + ch] & 1) << i;
    }

    if (total_len < IV_SIZE + HASH_SIZE || total_len > MAX_MSG_SIZE)
        return 0;

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
        return 0;

    unsigned char extracted_hash[HASH_SIZE];
    memcpy(extracted_hash, plaintext + dec_len - HASH_SIZE, HASH_SIZE);
    plaintext[dec_len - HASH_SIZE] = '\0';

    unsigned char calc_hash[HASH_SIZE];
    sha256(plaintext, dec_len - HASH_SIZE, calc_hash);

    if (memcmp(extracted_hash, calc_hash, HASH_SIZE) != 0)
    {
        // Hash mismatch: output data is invalid (incorrect key or corrupted image data)
        fprintf(stderr, "Decryption failed: Incorrect key or data corrupted.\n");
        return 0;
    }

    printf("Decrypted Message: %s\n", plaintext);
    for (int y = 0; y < height; y++)
        free(rows[y]);
    free(rows);
    free(combined);
    return 1;
}

/*
 * embed_message_bmp - Hide an encrypted message inside a BMP image.
 * @infile: path to the input BMP file.
 * @outfile: path to save the output BMP file with the hidden message.
 * @msg: the message string to hide.
 * @key: the passphrase for encrypting the message.
 * Returns: 1 on success, 0 on failure.
 *
 * This function encrypts the message (with a SHA-256 hash for integrity) using AES-256-CBC,
 * then embeds the IV and ciphertext into the BMP's pixel data. It uses the LSB of each byte in the pixel array to store the bits.
 * The length of the hidden data is stored in the LSB of the first 32 bytes of the pixel data.
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

    // Compute hash of message and prepare plaintext (message + hash)
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
 * This function reads the 32-bit length from the LSB of the first 32 pixel bytes in the BMP data, then reconstructs the
 * hidden data bits from the remaining pixel bytes. It decrypts this data and verifies the appended SHA-256 hash.
 * If the hash matches, the original message is printed to stdout.
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

    // Read the hidden data length from the LSB of the first 32 pixel bytes
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

    unsigned char extracted_hash[HASH_SIZE];
    memcpy(extracted_hash, plaintext + dec_len - HASH_SIZE, HASH_SIZE);
    plaintext[dec_len - HASH_SIZE] = '\0';
    unsigned char calc_hash[HASH_SIZE];
    sha256(plaintext, dec_len - HASH_SIZE, calc_hash);
    if (memcmp(extracted_hash, calc_hash, HASH_SIZE) != 0)
    {
        // If hashes do not match, the message is not valid (wrong key or tampered data)
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

/*
 * embed_message_jpg - Hide an encrypted message inside a JPEG image.
 * @infile: path to the input JPEG file.
 * @outfile: path to save the output JPEG file with the hidden message.
 * @msg: the message string to hide.
 * @key: the passphrase for encrypting the message.
 * Returns: 1 on success, 0 on failure.
 *
 * This function encrypts the message (with SHA-256 hash appended) using AES-256-CBC,
 * and embeds the encrypted data into a custom JPEG APP1 marker. It adds a marker identified by 'STEGO' that contains
 * the IV and ciphertext. The JPEG image is recompressed (with quality 90) to include this hidden data.
 */
int embed_message_jpg(const char *infile, const char *outfile, const char *msg, const char *key)
{
    FILE *in = fopen(infile, "rb");
    if (!in)
        return 0;

    struct jpeg_decompress_struct cinfo;
    struct jpeg_error_mgr jerr;
    cinfo.err = jpeg_std_error(&jerr);
    jpeg_create_decompress(&cinfo);
    jpeg_stdio_src(&cinfo, in);
    jpeg_read_header(&cinfo, TRUE);
    jpeg_start_decompress(&cinfo);
    int width = cinfo.output_width;
    int height = cinfo.output_height;
    int comps = cinfo.output_components;
    int row_stride = width * comps;

    unsigned char *image_buffer = malloc(row_stride * height);

    // Decompress the JPEG image and read all scanlines into image_buffer
    for (int i = 0; i < height; i++)
    {
        unsigned char *rowptr = image_buffer + i * row_stride;
        jpeg_read_scanlines(&cinfo, &rowptr, 1);
    }
    jpeg_finish_decompress(&cinfo);
    jpeg_destroy_decompress(&cinfo);
    fclose(in);

    // Compute SHA-256 hash of the message for integrity
    unsigned char hash[HASH_SIZE];
    sha256((const unsigned char *)msg, strlen(msg), hash);
    int payload_len = strlen(msg) + HASH_SIZE;
    unsigned char plaintext[MAX_MSG_SIZE];

    // Prepare plaintext by concatenating message and hash
    memcpy(plaintext, msg, strlen(msg));
    memcpy(plaintext + strlen(msg), hash, HASH_SIZE);

    // Generate random IV for AES encryption
    unsigned char iv[IV_SIZE];
    if (!RAND_bytes(iv, IV_SIZE))
        return 0;

    unsigned char ciphertext[MAX_MSG_SIZE + EVP_MAX_BLOCK_LENGTH];

    // Encrypt plaintext using AES-256-CBC
    int enc_len = aes_encrypt(plaintext, payload_len, key, ciphertext, iv);
    int total_len = strlen(JPEG_MARKER_TAG) + IV_SIZE + enc_len;

    // Create marker data: "STEGO" tag + IV + ciphertext
    unsigned char *marker_data = malloc(total_len);
    memcpy(marker_data, JPEG_MARKER_TAG, strlen(JPEG_MARKER_TAG));
    memcpy(marker_data + strlen(JPEG_MARKER_TAG), iv, IV_SIZE);
    memcpy(marker_data + strlen(JPEG_MARKER_TAG) + IV_SIZE, ciphertext, enc_len);

    FILE *out = fopen(outfile, "wb");
    if (!out)
        return 0;

    struct jpeg_compress_struct cinfo_out;
    struct jpeg_error_mgr jerr_out;
    cinfo_out.err = jpeg_std_error(&jerr_out);
    jpeg_create_compress(&cinfo_out);
    jpeg_stdio_dest(&cinfo_out, out);

    cinfo_out.image_width = width;
    cinfo_out.image_height = height;
    cinfo_out.input_components = comps;
    cinfo_out.in_color_space = (comps == 3) ? JCS_RGB : JCS_GRAYSCALE;

    jpeg_set_defaults(&cinfo_out);
    jpeg_set_quality(&cinfo_out, 90, TRUE);

    jpeg_start_compress(&cinfo_out, TRUE);

    // Insert custom APP1 marker containing the hidden data
    jpeg_write_marker(&cinfo_out, JPEG_MARKER_ID, marker_data, total_len);

    for (int i = 0; i < height; i++)
    {
        unsigned char *rowptr = image_buffer + i * row_stride;
        jpeg_write_scanlines(&cinfo_out, &rowptr, 1);
    }

    jpeg_finish_compress(&cinfo_out);
    jpeg_destroy_compress(&cinfo_out);

    fclose(out);
    free(image_buffer);
    free(marker_data);
    return 1;
}

/*
 * extract_message_jpg - Extract a hidden message from a JPEG image.
 * @infile: path to the JPEG image file containing a hidden message.
 * @key: the passphrase used to encrypt the hidden message.
 * Returns: 1 if a hidden message is found and extracted, 0 if not found or on failure.
 *
 * This function scans the JPEG file for an APP1 marker starting with 'STEGO'. If found, it extracts the IV and ciphertext from
 * the marker, decrypts the data with the provided key, and verifies the SHA-256 hash. If the hash is valid, the hidden message
 * is printed to stdout.
 */
int extract_message_jpg(const char *infile, const char *key)
{
    FILE *in = fopen(infile, "rb");
    if (!in)
        return 0;

    struct jpeg_decompress_struct cinfo;
    struct jpeg_error_mgr jerr;
    cinfo.err = jpeg_std_error(&jerr);
    jpeg_create_decompress(&cinfo);
    jpeg_save_markers(&cinfo, JPEG_MARKER_ID, 0xFFFF);
    jpeg_stdio_src(&cinfo, in);
    jpeg_read_header(&cinfo, TRUE);

    // Iterate through saved markers to find the "STEGO" marker
    jpeg_saved_marker_ptr marker = cinfo.marker_list;
    while (marker)
    {
        if (marker->marker == JPEG_MARKER_ID && marker->data_length > strlen(JPEG_MARKER_TAG))
        {
            // STEGO marker found: retrieve IV and ciphertext from marker->data
            if (memcmp(marker->data, JPEG_MARKER_TAG, strlen(JPEG_MARKER_TAG)) == 0)
            {
                unsigned char *iv = marker->data + strlen(JPEG_MARKER_TAG);
                unsigned char *cipher = iv + IV_SIZE;
                int cipher_len = marker->data_length - strlen(JPEG_MARKER_TAG) - IV_SIZE;

                unsigned char plaintext[MAX_MSG_SIZE];
                int dec_len = aes_decrypt(cipher, cipher_len, key, plaintext, iv);

                // Decrypt the ciphertext; if failed or message too short, abort extraction
                if (dec_len <= HASH_SIZE)
                {
                    jpeg_destroy_decompress(&cinfo);
                    fclose(in);
                    return 0;
                }

                unsigned char extracted_hash[HASH_SIZE];
                memcpy(extracted_hash, plaintext + dec_len - HASH_SIZE, HASH_SIZE);
                plaintext[dec_len - HASH_SIZE] = '\0';

                unsigned char calc_hash[HASH_SIZE];
                sha256(plaintext, dec_len - HASH_SIZE, calc_hash);

                // Verify integrity: compare extracted hash with computed hash of plaintext
                if (memcmp(extracted_hash, calc_hash, HASH_SIZE) == 0)
                {
                    printf("Decrypted Message: %s\n", plaintext);
                    jpeg_destroy_decompress(&cinfo);
                    fclose(in);
                    return 1;
                }
                else
                {
                    fprintf(stderr, "Decryption failed: Incorrect key or data corrupted.\n");
                    jpeg_destroy_decompress(&cinfo);
                    fclose(in);
                    return 0;
                }
            }
        }
        marker = marker->next;
    }

    jpeg_destroy_decompress(&cinfo);
    fclose(in);
    fprintf(stderr, "No embedded message found in JPEG.");
    return 0;
}

/*
 * main - Entry point of the steganography CLI application.
 * @argc: number of command-line arguments.
 * @argv: array of command-line argument strings.
 * Returns: 0 on successful execution, or 1 on error (e.g., invalid usage or failure to process).
 *
 * This function parses the command-line arguments to determine the mode (encrypt or decrypt), input file, output file, passkey,
 * and message (if encrypting). It then calls the appropriate embed or extract function for the given image format.
 */
int main(int argc, char *argv[])
{
    char *method = NULL, *input_file = NULL, *output_file = NULL, *passkey = NULL, *message = NULL;

    // Parse command-line options (-m, -i, -o, -p, -s)
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

    // Validate required arguments are provided (method, input file, passkey)
    if (!method || !input_file || !passkey)
    {
        fprintf(stderr, "Usage: %s -m <method> -i <input> -p <passkey> [-s <message>] [-o <output>]\n", argv[0]);
        return 1;
    }

    const char *ext = get_file_ext(input_file);

    // Encryption mode selected
    if (strcasecmp(method, "encrypt") == 0)
    {
        // Check that message (-s) and output file (-o) are specified for encryption
        if (!message || !output_file)
        {
            fprintf(stderr, "Encryption requires -s <message> and -o <output>\n");
            return 1;
        }

        // Call the appropriate embedding function based on the input file extension
        if (strcasecmp(ext, "png") == 0)
        {
            if (embed_message_png(input_file, output_file, message, passkey))
                printf("Message successfully embedded in PNG.\n");
            else
                fprintf(stderr, "Failed to embed message in PNG.\n");
        }
        else if (strcasecmp(ext, "bmp") == 0)
        {
            if (embed_message_bmp(input_file, output_file, message, passkey))
                printf("Message successfully embedded in BMP.\n");
            else
                fprintf(stderr, "Failed to embed message in BMP.\n");
        }
        else if (strcasecmp(ext, "jpg") == 0 || strcasecmp(ext, "jpeg") == 0)
        {
            if (embed_message_jpg(input_file, output_file, message, passkey))
                printf("Message successfully embedded in JPG.\n");
            else
                fprintf(stderr, "Failed to embed message in JPG.\n");
        }
        else
        {
            fprintf(stderr, "Unsupported format for encryption: %s\n", ext);
        }
    }

    // Decryption mode selected
    else if (strcasecmp(method, "decrypt") == 0)
    {
        // Call the appropriate extraction function based on the input file extension
        if (strcasecmp(ext, "png") == 0)
        {
            if (!extract_message_png(input_file, passkey))
                fprintf(stderr, "Failed to extract message from PNG.\n");
        }
        else if (strcasecmp(ext, "bmp") == 0)
        {
            if (!extract_message_bmp(input_file, passkey))
                fprintf(stderr, "Failed to extract message from BMP.\n");
        }
        else if (strcasecmp(ext, "jpg") == 0 || strcasecmp(ext, "jpeg") == 0)
        {
            if (!extract_message_jpg(input_file, passkey))
                fprintf(stderr, "Failed to extract message from JPG.\n");
        }
        else
        {
            fprintf(stderr, "Unsupported format for decryption: %s\n", ext);
        }
    }
    else
    {
        // Handle unknown method input
        fprintf(stderr, "Unknown method: %s\n", method);
    }

    return 0;
}