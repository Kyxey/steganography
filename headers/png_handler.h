#ifndef PNG_HANDLER_H
#define PNG_HANDLER_H

// Function prototypes for PNG steganography handlers
int embed_message_png(const char *infile, const char *outfile, const char *msg, const char *key);
int extract_message_png(const char *infile, const char *key);

#endif // PNG_HANDLER_H