#include "rsa.h"
#include "numtheory.h"
#include "randstate.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <gmp.h>

// This function creates parts of a new RSA public key including two large primes p and q, their product n,
// and the public exponent e.
// This function takes in as parameters mpz_t p, mpz_t q, mpz_t n, mpz_t e, uint64_t nbits, and uint64_t iters.
void rsa_make_pub(mpz_t p, mpz_t q, mpz_t n, mpz_t e, uint64_t nbits, uint64_t iters) {
    uint64_t pbits = (random() % (2 * nbits / 4)) + (nbits / 4);
    uint64_t qbits = nbits - pbits;
    make_prime(p, pbits, iters);
    make_prime(q, qbits, iters);
    mpz_mul(n, p, q);

    mpz_t p_minus_one;
    mpz_init(p_minus_one);
    mpz_sub_ui(p_minus_one, p, 1);
    mpz_t q_minus_one;
    mpz_init(q_minus_one);
    mpz_sub_ui(q_minus_one, q, 1);
    mpz_t totient;
    mpz_init(totient);
    mpz_mul(totient, p_minus_one, q_minus_one);

    mpz_t gcd_e_totient;
    mpz_init(gcd_e_totient);
    do {
        mpz_urandomb(e, state, nbits);
        gcd(gcd_e_totient, e, totient);
    } while (mpz_cmp_ui(gcd_e_totient, 1) > 0);

    mpz_clear(p_minus_one);
    mpz_clear(q_minus_one);
    mpz_clear(totient);
    mpz_clear(gcd_e_totient);
}

// This function writes a public RSA key to pbfile.
// This function takes in as parameters mpz_t n, mpz_t e, mpz_t s, char username[], and a FILE *pbfile.
void rsa_write_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fprintf(pbfile, "%Zx\n", n);
    gmp_fprintf(pbfile, "%Zx\n", e);
    gmp_fprintf(pbfile, "%Zx\n", s);
    fprintf(pbfile, "%s\n", username);
}

// This function reads a public RSA key from pbfile.
// This function takes in as parameters mpz_t n, mpz_t e, mpz_t s, char username[], and FILE *pbfile.
void rsa_read_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fscanf(pbfile, "%Zx\n", n);
    gmp_fscanf(pbfile, "%Zx\n", e);
    gmp_fscanf(pbfile, "%Zx\n", s);
    fscanf(pbfile, "%s\n", username);
}

// This function creates a new RSA private key.
// This function takes in as parameters mpz_t d which is where the RSA private key will be stored,
// mpz_t e which is the public exponent, mpz_t p which is a prime number, and mpz_t q which is another prime number.
void rsa_make_priv(mpz_t d, mpz_t e, mpz_t p, mpz_t q) {
    mpz_t p_minus_one;
    mpz_init(p_minus_one);
    mpz_sub_ui(p_minus_one, p, 1);
    mpz_t q_minus_one;
    mpz_init(q_minus_one);
    mpz_sub_ui(q_minus_one, q, 1);
    mpz_t totient;
    mpz_init(totient);
    mpz_mul(totient, p_minus_one, q_minus_one);

    mod_inverse(d, e, totient);

    mpz_clear(p_minus_one);
    mpz_clear(q_minus_one);
    mpz_clear(totient);
}

// This function writes a private RSA key to pvfile.
// This function takes in as parameters mpz_t n, mpz_t d, and FILE *pvfile.
void rsa_write_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fprintf(pvfile, "%Zx\n", n);
    gmp_fprintf(pvfile, "%Zx\n", d);
}

// This function reads a private RSA key from pvfile.
// This function takes in as parameters mpz_t n, mpz_t d, and FILE *pvfile.
void rsa_read_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fscanf(pvfile, "%Zx\n", n);
    gmp_fscanf(pvfile, "%Zx\n", d);
}

// This function performs RSA encryption, computing ciphertext c by encrypting message m using public exponent e and
// modulus n.
// This function takes in as parameters mpz_t c, mpz_t m, mpz_t e, and mpz_t n.
void rsa_encrypt(mpz_t c, mpz_t m, mpz_t e, mpz_t n) {
    pow_mod(c, m, e, n);
}

// This function encrypts the contents of infile, writing the encrypted contents to outfile.
// This function takes in as parameters FILE *infile, FILE *outfile, mpz_t n, and mpz_t e.
void rsa_encrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t e) {
    size_t k = (mpz_sizeinbase(n, 2) - 1) / 8;

    uint8_t *array = (uint8_t *) calloc(k, sizeof(uint8_t));

    array[0] = 0xFF;

    size_t j;
    mpz_t m;
    mpz_init(m);
    mpz_t c;
    mpz_init(c);
    while (feof(infile) == 0) {
        j = fread(array + 1, sizeof(uint8_t), k - 1, infile);
        mpz_import(m, j + 1, 1, sizeof(uint8_t), 1, 0, array);
        rsa_encrypt(c, m, e, n);
        gmp_fprintf(outfile, "%Zx\n", c);
    }

    mpz_clear(m);
    mpz_clear(c);
    free(array);
}

// This function performs RSA decryption, computing message m by decrypting ciphertext c using private key d and
// public modulus n.
// This function takes in as parameters mpz_t m, mpz_t c, mpz_t d, and mpz_t n.
void rsa_decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n) {
    pow_mod(m, c, d, n);
}

// This function decrypts the contents of infile, writing the decrypted contents to outfile.
// This function takes in as parameters FILE *infile, FILE *outfile, mpz_t n, and mpz_t d.
void rsa_decrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t d) {
    size_t k = (mpz_sizeinbase(n, 2) - 1) / 8;

    uint8_t *array = (uint8_t *) calloc(k, sizeof(uint8_t));

    mpz_t c;
    mpz_init(c);
    mpz_t m;
    mpz_init(m);
    size_t j;
    while (feof(infile) == 0) {
        gmp_fscanf(infile, "%Zx\n", c);
        if (mpz_cmp_ui(c, 0) > 0) {
            rsa_decrypt(m, c, d, n);
            mpz_export(array, &j, 1, sizeof(uint8_t), 1, 0, m);
            fwrite(array + 1, sizeof(uint8_t), j - 1, outfile);
        }
    }

    mpz_clear(c);
    mpz_clear(m);
    free(array);
}

// This function performs RSA signing, producing signature s by signing message m using private key d and public
// modulus n.
// This function takes in as parameters mpz_t s, mpz_t m, mpz_t d, and mpz_t n
void rsa_sign(mpz_t s, mpz_t m, mpz_t d, mpz_t n) {
    pow_mod(s, m, d, n);
}

// This function performs RSA verification, returning true if signature s is verified and false otherwise.
// This function takes in as parameters mpz_t m, mpz_t s, mpz_t e, and mpz_t n.
bool rsa_verify(mpz_t m, mpz_t s, mpz_t e, mpz_t n) {
    mpz_t t;
    mpz_init(t);
    pow_mod(t, s, e, n);

    if (mpz_cmp(t, m) == 0) {
        mpz_clear(t);
        return true;
    } else {
        mpz_clear(t);
        return false;
    }
}
