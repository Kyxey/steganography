#ifndef BMP_HANDLER_H
#define BMP_HANDLER_H

// Function prototypes for BMP steganography handlers
int embed_message_bmp(const char *infile, const char *outfile, const char *msg, const char *key);
int extract_message_bmp(const char *infile, const char *key);

#endif // BMP_HANDLER_H