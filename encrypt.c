#include "numtheory.h"
#include "randstate.h"
#include "rsa.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <gmp.h>

#define OPTIONS "i:o:n:vh"

void help_message(void) {
    fprintf(stderr, "SYNOPSIS\n"
                    "   Encrypts data using RSA encryption.\n"
                    "   Encrypted data is decrypted by the decrypt program.\n"
                    "\n"
                    "USAGE\n"
                    "   ./encrypt [-hv] [-i infile] [-o outfile] -n pubkey\n"
                    "\n"
                    "OPTIONS\n"
                    "   -h              Display program help and usage.\n"
                    "   -v              Display verbose program output.\n"
                    "   -i infile       Input file of data to encrypt (default: stdin).\n"
                    "   -o outfile      Output file for encrypted data (default: stdout).\n"
                    "   -n pbfile       Public key file (default: rsa.pub).\n");
}

int main(int argc, char **argv) {
    int opt = 0;
    FILE *infile = stdin;
    FILE *outfile = stdout;
    char *pbname = "rsa.pub";
    FILE *pbfile;
    bool verbose = false;

    // Parsing command-line options using getopt() and handling them accordingly.
    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
        case 'i':
            if ((infile = fopen(optarg, "r")) == NULL) {
                fprintf(stderr, "%s: No such file or directory\n", optarg);
                return EXIT_FAILURE;
            }
            break;
        case 'o':
            if ((outfile = fopen(optarg, "w")) == NULL) {
                fprintf(stderr, "%s: No such file or directory\n", optarg);
                return EXIT_FAILURE;
            }
            break;
        case 'n': pbname = optarg; break;
        case 'v': verbose = true; break;
        case 'h': help_message(); return EXIT_SUCCESS;
        default: help_message(); return EXIT_FAILURE;
        }
    }

    // Opening the public key file using fopen(). Printing a helpful error and exiting the program in the event
    // of failure.
    pbfile = fopen(pbname, "r");
    if (pbfile == NULL) {
        fprintf(stderr, "%s: No such file or directory\n", pbname);
        return EXIT_FAILURE;
    }

    mpz_t n;
    mpz_init(n);
    mpz_t e;
    mpz_init(e);
    mpz_t s;
    mpz_init(s);
    mpz_t m;
    mpz_init(m);
    char username[256];

    // Reading the public key from the opened public key file.
    rsa_read_pub(n, e, s, username, pbfile);

    // If verbose output is enabled, print the username, the signature s, the public modulus n, and the
    // public exponent e each with a trailing newline.
    if (verbose) {
        printf("user = %s\n", username);
        gmp_printf("s (%d bits) = %Zd\n", mpz_sizeinbase(s, 2), s);
        gmp_printf("n (%d bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("e (%d bits) = %Zd\n", mpz_sizeinbase(e, 2), e);
    }

    // Converting the username that was read in to an mpz_t.
    mpz_set_str(m, username, 62);
    // Verifying the signature. If the signature couldn't be verified, report an error and exit the program.
    if (rsa_verify(m, s, e, n) == false) {
        fprintf(stderr, "Error: the signature was not verified.\n");
        fclose(infile);
        fclose(outfile);
        fclose(pbfile);
        mpz_clear(n);
        mpz_clear(e);
        mpz_clear(s);
        mpz_clear(m);
        return EXIT_FAILURE;
    }

    // Encrypting the file using rsa_encrypt_file().
    rsa_encrypt_file(infile, outfile, n, e);

    // Closing infile, outfile, and the public key file.
    fclose(infile);
    fclose(outfile);
    fclose(pbfile);
    // Clearing all the mpz_t variables used in the program.
    mpz_clear(n);
    mpz_clear(e);
    mpz_clear(s);
    mpz_clear(m);

    return EXIT_SUCCESS;
}
