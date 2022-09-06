#include "numtheory.h"
#include "randstate.h"
#include "rsa.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <gmp.h>

#define OPTIONS "b:i:n:d:s:vh"

void help_message(void) {
    fprintf(stderr, "SYNOPSIS\n"
                    "   Generates an RSA public/private key pair.\n"
                    "\n"
                    "USAGE\n"
                    "   ./keygen [-hv] [-b bits] -n pbfile -d pvfile\n"
                    "\n"
                    "OPTIONS\n"
                    "   -h              Display program help and usage.\n"
                    "   -v              Display verbose program output.\n"
                    "   -b bits         Minimum bits needed for public key n (default: 256).\n"
                    "   -i confidence   Miller-Rabin iterations for testing primes (default: 50).\n"
                    "   -n pbfile       Public key file (default: rsa.pub).\n"
                    "   -d pvfile       Private key file (default: rsa.priv).\n"
                    "   -s seed         Random seed for testing.\n");
}

int main(int argc, char **argv) {
    int opt = 0;
    char *temp;
    uint64_t bits = 256;
    uint64_t iters = 50;
    char *pbname = "rsa.pub";
    FILE *pbfile;
    char *pvname = "rsa.priv";
    FILE *pvfile;
    uint64_t seed = time(NULL);
    bool verbose = false;

    // Parsing command-line options using getopt() and handling them accordingly.
    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
        case 'b': bits = atoi(optarg); break;
        case 'i':
            temp = optarg;
            if (atoi(temp) == 0) {
                break;
            } else {
                iters = atoi(temp);
                break;
            }
        case 'n': pbname = optarg; break;

        case 'd': pvname = optarg; break;
        case 's':
            temp = optarg;
            if (atoi(temp) == 0) {
                break;
            } else {
                seed = atoi(temp);
                break;
            }
        case 'v': verbose = true; break;
        case 'h': help_message(); return EXIT_SUCCESS;
        default: help_message(); return EXIT_FAILURE;
        }
    }

    // Opening the public key file using fopen(). Printing a helpful error and exiting the program in the event
    // of failure.
    pbfile = fopen(pbname, "w");
    if (pbfile == NULL) {
        fprintf(stderr, "Error: failed to open file.\n");
        return EXIT_FAILURE;
    }

    // Opening the private key file using fopen(). Printing a helpful error and exiting the program in the event
    // of failure.
    pvfile = fopen(pvname, "w");
    if (pvfile == NULL) {
        fprintf(stderr, "Error: failed to open file.\n");
        return EXIT_FAILURE;
    }

    // Using fchmod() and fileno() to make sure that the private key file permissions are set to 0600
    // which indicates read and write permissions for the user and no permissions for anyone else.
    fchmod(fileno(pvfile), 0600);

    // Initializing the random state using randstate_init() and the set seed.
    randstate_init(seed);

    mpz_t s;
    mpz_init(s);
    mpz_t p;
    mpz_init(p);
    mpz_t q;
    mpz_init(q);
    mpz_t n;
    mpz_init(n);
    mpz_t e;
    mpz_init(e);
    mpz_t d;
    mpz_init(d);

    // Making the public key using rsa_make_pub().
    rsa_make_pub(p, q, n, e, bits, iters);
    // Making the private key using rsa_make_priv().
    rsa_make_priv(d, e, p, q);

    // Getting the current user's name as a string using getenv() and converting the username
    // into an mpz_t with mpz_set_str(), specifying the base as 62.
    mpz_set_str(s, getenv("USER"), 62);
    // Using rsa_sign() to compute the signature of the username.
    rsa_sign(s, s, d, n);

    // Writing the computed public key to its respective file.
    rsa_write_pub(n, e, s, getenv("USER"), pbfile);
    // Writing the computed private key to its respective file.
    rsa_write_priv(n, d, pvfile);

    // If verbose output was enabled, print the username, the signature s, the first large prime p, the second
    // large prime q, the public modulus n, the public exponent e, and the private key d each with a trailing
    // newline.
    if (verbose) {
        printf("user = %s\n", getenv("USER"));
        gmp_printf("s (%d bits) = %Zd\n", mpz_sizeinbase(s, 2), s);
        gmp_printf("p (%d bits) = %Zd\n", mpz_sizeinbase(p, 2), p);
        gmp_printf("q (%d bits) = %Zd\n", mpz_sizeinbase(q, 2), q);
        gmp_printf("n (%d bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
        gmp_printf("e (%d bits) = %Zd\n", mpz_sizeinbase(e, 2), e);
        gmp_printf("d (%d bits) = %Zd\n", mpz_sizeinbase(d, 2), d);
    }

    // Closing the public and private key files.
    fclose(pbfile);
    fclose(pvfile);
    // Clearing the random state with randstate_clear().
    randstate_clear();
    // Clearing all the mpz_t variables used in the program.
    mpz_clear(s);
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
    mpz_clear(e);
    mpz_clear(d);

    return EXIT_SUCCESS;
}
