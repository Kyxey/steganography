#ifndef JPG_HANDLER_H
#define JPG_HANDLER_H

// JPEG marker definitions for steganography
#define JPEG_MARKER_ID 0xE1     // JPEG APP1 marker code used for steganography
#define JPEG_MARKER_TAG "STEGO" // Tag to identify custom JPEG marker containing hidden data

// Function prototypes for JPEG steganography handlers
int embed_message_jpg(const char *infile, const char *outfile, const char *msg, const char *key);
int extract_message_jpg(const char *infile, const char *key);

#endif // JPG_HANDLER_H