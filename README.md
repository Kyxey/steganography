# Steganography

This CLI-based tool does Steganography on images. It performs both encrypting and decrypting processes.

## Table of Contents

- [Steganography](#steganography)
  - [Table of Contents](#table-of-contents)
  - [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Compiling](#compiling)
  - [Usage](#usage)
    - [Limitations](#limitations)
    - [General Usage](#general-usage)
    - [Phase 1: Encryption](#phase-1-encryption)
    - [Phase 2: Decryption](#phase-2-decryption)
  - [Next Steps](#next-steps)
  - [Contributions](#contributions)
  - [Legal Disclaimer](#legal-disclaimer)

## Getting Started

This application is written with C programming language, and thus can be compiled with any modern C compilers of choice. The examples, however, are written using `gcc`. All of the code snippets are ran and tested on macOS 15.5 (Sequoia).

### Prerequisites

You'll need the following libraries and tools to be able to build and compile the code:

- OpenSSL (For encrypting/decrypting the messages)
- LibPNG (For processing `PNG` images)
- GCC (Or any other modern C compilers)

You can install the required libraries and tools (e.g. OpenSSL and it's development tools), and get them ready for the compile with the following commands:

**macOS**:

```bash
brew install openssl && brew unlink openssl && brew link openssl --force && brew install libffi && brew install libpng
```

**Linux**:

```bash
sudo apt update
sudo apt install -y libssl-dev libffi-dev libpng-dev
```

### Compiling

Th command below builds and compiles the app while bundling it with the required libraries, and saves the output to a file named `steg` in the same directory.

**macOS**:

```bash
gcc steg.c -o steg \
    -I$(brew --prefix openssl)/include \
    -L$(brew --prefix openssl)/lib \
    -I$(brew --prefix libpng)/include \
    -L$(brew --prefix libpng)/lib \
    -lssl -lcrypto -lpng
```

**Linux**:

```bash
gcc steg.c -o steg \
    -I/usr/include \
    -L/usr/lib \
    -lssl -lcrypto -lpng
```

## Usage

Using the app is very simple and straightforward. It has the two phases of encryption (embedding a message into an image file using a passkey), and decryption (retrieving the encrypted message from the image file using the same passkey). However, before proceeding any further, there are some important limitations which you need to be aware of.

### Limitations

The app currently has some serious limitations. Some of the most important ones are listed below:

- It only supports `BMP` and `PNG` images.
- The message string is limited in size.

### General Usage

The CLI app is generally defined as followed:

```bash
./steg -m [METHOD] -i [INPUT_FILE_ADDRESS] -o [OUTPUT_FILE_ADDRESS] -p [PASSKEY] -s [MESSAGE]
```

The options and arguments are defined as below:

- **`-m` or `-M` - required**: The method of the app to be ran with. Possible values are `encrypt` and `decrypt` for their respective functionality.
- **`-i` or `-I` - required**: The address to the input image file. For example: `foo/bar/input.bmp`. This file will be used either for embedding a message into it, or retrieving the message from it, based on the selected method.
- **`-o` or `-O` - optional**: The address to the output image file. For example: `foo/bar/output.bmp`. This file will be used to store the output image file that contains the encrypted message in. Thus it's only required if the selected method is `encrypt`, and needs to be different from the input file.
- **`-p` or `-P` - required**: The passkey to be used to either encrypt or decrypt the message to or from the image. For example: `MyStrongPassKey1234`.
- **`-s` or `-S` - optional**: The string message that needs to be encrypted and then embedded into the image file. It is only required when using the `encrypt` method. Example: `"My important, secret message\!"`

**IMPORTANT NOTE 1**: Don't forget to escape the special characters such as `!`, `/` etc. in the message string. This means to prefix the respective character with `\`, such as `\!` or `\/`.

**IMPORTANT NOTE 2**: Please pay attention to the file extensions. The input and output files must have the exact same extensions, otherwise you'll end up with unexpected behavior.

### Phase 1: Encryption

After compiling, you can encrypt and then embed a string message into an image file, using a passkey, by running the command below:

```bash
./steg -m encrypt -i input.bmp -o output.bmp -p myPasskey -s "My important, secret message\!"
```

Then send the output image to whoever you want to be able to read the message, along with the passkey. Then they can give the image to this app as the input file, with the same passkey, and retrieve your message from it.

### Phase 2: Decryption

After receiving an image that has a hidden encrypted message embedded inside it, you can decrypt and retrieve the embedded message from the image file, using the same passkey that was used to encrypt it as shown below:

```bash
./steg -m decrypt -i output.bmp -p myPasskey
```

If the passkey is correct, you should see the message in the output like:

```
Decrypted Message: My important, secret message!
```

## Next Steps

The following features are to be implemented soon:

- Support more image types such as `JPG`.
- Increase the message size without causing memory leaks and unpredicted behavior.
- Separate the code across multiple files and maintain a good folder structure for better readability and maintainability.

## Contributions

Any sort of contributions, including but not limited to pull requests, comments, issues, forks, suggestions etc. is welcomed and highly appreciated and encouraged. Please feel free to contact me for more details.

## Legal Disclaimer

This is a fully educational project. The original author(s) of this project have no responsibilities for any sort of illegal usages.
