#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <jpeglib.h>
#include <jerror.h>
#include "headers/jpg_handler.h"
#include "headers/crypto_utils.h"

/*
 * embed_message_jpg - Hide an encrypted message inside a JPEG image.
 * @infile: path to the input JPEG file.
 * @outfile: path to save the output JPEG file with the hidden message.
 * @msg: the message string to hide.
 * @key: the passphrase for encrypting the message.
 * Returns: 1 on success, 0 on failure.
 *
 * This function encrypts the message (with SHA-256 hash appended) using AES-256-CBC,
 * and embeds the encrypted data into a custom JPEG APP1 marker. It adds a marker
 * identified by 'STEGO' that contains the IV and ciphertext. The JPEG image is
 * recompressed (with quality 90) to include this hidden data.
 */
int embed_message_jpg(const char *infile, const char *outfile, const char *msg, const char *key)
{
    FILE *in = fopen(infile, "rb");
    if (!in)
        return 0;

    // Initialize JPEG decompression
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

    // Decompress the JPEG image fully into image_buffer
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
    {
        free(image_buffer);
        return 0;
    }
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
    {
        free(image_buffer);
        free(marker_data);
        return 0;
    }

    // Initialize JPEG compression
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

    // Write scanlines from the original image data
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
 * This function scans the JPEG file for an APP1 marker starting with 'STEGO'. If found,
 * it extracts the IV and ciphertext from the marker, decrypts the data with the provided key,
 * and verifies the SHA-256 hash. If the hash is valid, the hidden message is printed to stdout.
 */
int extract_message_jpg(const char *infile, const char *key)
{
    FILE *in = fopen(infile, "rb");
    if (!in)
        return 0;

    // Initialize JPEG decompression and marker saving
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
            if (memcmp(marker->data, JPEG_MARKER_TAG, strlen(JPEG_MARKER_TAG)) == 0)
            {
                // STEGO marker found: retrieve IV and ciphertext
                unsigned char *iv = marker->data + strlen(JPEG_MARKER_TAG);
                unsigned char *cipher = iv + IV_SIZE;
                int cipher_len = marker->data_length - strlen(JPEG_MARKER_TAG) - IV_SIZE;
                unsigned char plaintext[MAX_MSG_SIZE];
                int dec_len = aes_decrypt(cipher, cipher_len, key, plaintext, iv);

                // If decryption failed or message too short, abort extraction
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