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
                    "   Decrypts data using RSA decryption.\n"
                    "   Encrypted data is encrypted by the encrypt program.\n"
                    "\n"
                    "USAGE\n"
                    "   ./decrypt [-hv] [-i infile] [-o outfile] -n privkey\n"
                    "\n"
                    "OPTIONS\n"
                    "   -h              Display program help and usage.\n"
                    "   -v              Display verbose program output.\n"
                    "   -i infile       Input file of data to decrypt (default: stdin).\n"
                    "   -o outfile      Output file for decrypted data (default: stdout).\n"
                    "   -n pvfile       Private key file (default: rsa.priv).\n");
}

int main(int argc, char **argv) {
    int opt = 0;
    FILE *infile = stdin;
    FILE *outfile = stdout;
    char *pvname = "rsa.priv";
    FILE *pvfile;
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
        case 'n': pvname = optarg; break;
        case 'v': verbose = true; break;
        case 'h': help_message(); return EXIT_SUCCESS;
        default: help_message(); return EXIT_FAILURE;
        }
    }

    // Opening the private key file using fopen(). Printing a helpful error and exiting the program in the event
    // of failure.
    pvfile = fopen(pvname, "r");
    if (pvfile == NULL) {
        fprintf(stderr, "%s: No such file or directory\n", pvname);
        return EXIT_FAILURE;
    }

    mpz_t n;
    mpz_init(n);
    mpz_t d;
    mpz_init(d);

    // Reading the private key from the opened private key file.
    rsa_read_priv(n, d, pvfile);

    // If verbose output is enabled, print the public modulus n and the private key d each with a
    // trailing newline.
    if (verbose) {
        gmp_printf("n (%d bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("d (%d bits) = %Zd\n", mpz_sizeinbase(d, 2), d);
    }

    // Decrypting the file using rsa_decrypt_file().
    rsa_decrypt_file(infile, outfile, n, d);

    // Closing infile, outfile, and the private key file.
    fclose(infile);
    fclose(outfile);
    fclose(pvfile);
    // Clearing all the mpz_t variables used in the program.
    mpz_clear(n);
    mpz_clear(d);

    return EXIT_SUCCESS;
}
