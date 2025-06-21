#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <png.h>

#define MAX_MSG_SIZE 1024
#define HASH_SIZE 32
#define IV_SIZE 16
#define LENGTH_HEADER_BITS 32

const char *get_file_ext(const char *filename)
{
    const char *dot = strrchr(filename, '.');
    return (!dot || dot == filename) ? "" : dot + 1;
}

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
    if ((total_len * 8 + LENGTH_HEADER_BITS) > (width * height * 3))
        return 0;

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
    if (compression != 0 || (bpp != 24 && bpp != 32))
    {
        free(buffer);
        return 0;
    }

    unsigned char hash[HASH_SIZE];
    sha256((const unsigned char *)msg, strlen(msg), hash);
    int payload_len = strlen(msg) + HASH_SIZE;
    unsigned char plaintext[MAX_MSG_SIZE];
    memcpy(plaintext, msg, strlen(msg));
    memcpy(plaintext + strlen(msg), hash, HASH_SIZE);

    unsigned char iv[IV_SIZE];
    if (!RAND_bytes(iv, IV_SIZE))
    {
        free(buffer);
        return 0;
    }
    unsigned char ciphertext[MAX_MSG_SIZE + EVP_MAX_BLOCK_LENGTH];
    int enc_len = aes_encrypt(plaintext, payload_len, key, ciphertext, iv);
    int total_len = IV_SIZE + enc_len;
    long cover_bytes = file_size - offset;
    if ((long)total_len * 8 + LENGTH_HEADER_BITS > cover_bytes)
    {
        free(buffer);
        return 0;
    }

    // Embed length in first 32 bytes of pixel data
    for (int i = 0; i < LENGTH_HEADER_BITS; i++)
    {
        int bit = (total_len >> i) & 1;
        buffer[offset + i] = (buffer[offset + i] & ~1) | bit;
    }

    // Embed encrypted data (IV + ciphertext) bits
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
    if (compression != 0 || (bpp != 24 && bpp != 32))
    {
        free(buffer);
        return 0;
    }

    int total_len = 0;
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
        fprintf(stderr, "Usage: %s -m <method> -i <input> -p <passkey> [-s <message>] [-o <output>]\n", argv[0]);
        return 1;
    }

    const char *ext = get_file_ext(input_file);
    if (strcasecmp(method, "encrypt") == 0)
    {
        if (!message || !output_file)
        {
            fprintf(stderr, "Encryption requires -s <message> and -o <output>\n");
            return 1;
        }
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
        else
        {
            fprintf(stderr, "Unsupported format for encryption: %s\n", ext);
        }
    }
    else if (strcasecmp(method, "decrypt") == 0)
    {
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
        else
        {
            fprintf(stderr, "Unsupported format for decryption: %s\n", ext);
        }
    }
    else
    {
        fprintf(stderr, "Unknown method: %s\n", method);
    }

    return 0;
}