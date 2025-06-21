#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> // for strcasecmp
#include <ctype.h>
#include "headers/bmp_handler.h"
#include "headers/png_handler.h"
#include "headers/jpg_handler.h"
#include "headers/crypto_utils.h"

// Extract the file extension from a filename
const char *get_file_ext(const char *filename)
{
    const char *dot = strrchr(filename, '.');
    return (!dot || dot == filename) ? "" : dot + 1;
}

int main(int argc, char *argv[])
{
    char *method = NULL, *input_file = NULL, *output_file = NULL;
    char *passkey = NULL, *message = NULL;

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

    // Validate required arguments (method, input file, passkey)
    if (!method || !input_file || !passkey)
    {
        fprintf(stderr, "Usage: %s -m <method> -i <input> -p <passkey> [-s <message>] [-o <output>]\n", argv[0]);
        return 1;
    }

    const char *ext = get_file_ext(input_file);

    // Encryption mode
    if (strcasecmp(method, "encrypt") == 0)
    {
        // Encryption requires message (-s) and output file (-o)
        if (!message || !output_file)
        {
            fprintf(stderr, "Encryption requires -s <message> and -o <output>\n");
            return 1;
        }
        // Dispatch to the appropriate embedding function based on file extension
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
    // Decryption mode
    else if (strcasecmp(method, "decrypt") == 0)
    {
        // Dispatch to the appropriate extraction function based on file extension
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
        // Unknown method
        fprintf(stderr, "Unknown method: %s\n", method);
    }

    return 0;
}