#include "numtheory.h"
#include "randstate.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <gmp.h>

// This function performs fast modular exponentiation, computing base raised to the exponent
// power modulo modulus, and storing the computed result in out.
// This function takes in as parameters mpz_t out which is where the computed result
// will be stored, mpz_t base, mpz_t exponent, and mpz_t modulus.
void pow_mod(mpz_t out, mpz_t base, mpz_t exponent, mpz_t modulus) {
    mpz_t v;
    mpz_init(v);
    mpz_set_ui(v, 1);
    mpz_t p;
    mpz_init(p);
    mpz_set(p, base);
    mpz_t temp_exponent;
    mpz_init(temp_exponent);
    mpz_set(temp_exponent, exponent);
    while (mpz_cmp_ui(temp_exponent, 0) > 0) {
        if (mpz_odd_p(temp_exponent) > 0) {
            mpz_mul(v, v, p);
            mpz_mod(v, v, modulus);
        }
        mpz_mul(p, p, p);
        mpz_mod(p, p, modulus);
        mpz_div_ui(temp_exponent, temp_exponent, 2);
    }
    mpz_set(out, v);
    mpz_clear(v);
    mpz_clear(p);
    mpz_clear(temp_exponent);
}

// This function conducts the Miller-Rabin primality test to indicate whether or not n is prime using
// iters number of Miller-Rabin iterations.
// This function takes in as parameters mpz_t n and a uint64_t iters.
// This function returns true if n might be prime and false if n is composite.
bool is_prime(mpz_t n, uint64_t iters) {
    mpz_t remainder;
    mpz_init(remainder);
    mpz_t s;
    mpz_init(s);
    mpz_t n_minus_one;
    mpz_init(n_minus_one);
    mpz_sub_ui(n_minus_one, n, 1);
    mpz_t r;
    mpz_init(r);
    mpz_set(r, n_minus_one);
    mpz_t random_generated;
    mpz_init(random_generated);
    mpz_t n_minus_three;
    mpz_init(n_minus_three);
    mpz_sub_ui(n_minus_three, n, 3);
    mpz_t y;
    mpz_init(y);
    mpz_t j;
    mpz_init(j);
    mpz_t s_minus_one;
    mpz_init(s_minus_one);
    mpz_t two;
    mpz_init(two);
    mpz_set_ui(two, 2);

    if (mpz_cmp_ui(n, 2) < 0) {
        mpz_clear(remainder);
        mpz_clear(s);
        mpz_clear(r);
        mpz_clear(n_minus_one);
        mpz_clear(random_generated);
        mpz_clear(n_minus_three);
        mpz_clear(y);
        mpz_clear(j);
        mpz_clear(s_minus_one);
        mpz_clear(two);
        return false;
    }

    mpz_mod_ui(remainder, n, 2);
    if (mpz_cmp_ui(n, 2) != 0 && mpz_cmp_ui(remainder, 0) == 0) {
        mpz_clear(remainder);
        mpz_clear(s);
        mpz_clear(r);
        mpz_clear(n_minus_one);
        mpz_clear(random_generated);
        mpz_clear(n_minus_three);
        mpz_clear(y);
        mpz_clear(j);
        mpz_clear(s_minus_one);
        mpz_clear(two);
        return false;
    }

    if (mpz_cmp_ui(n, 2) == 0 || mpz_cmp_ui(n, 3) == 0) {
        mpz_clear(remainder);
        mpz_clear(s);
        mpz_clear(r);
        mpz_clear(n_minus_one);
        mpz_clear(random_generated);
        mpz_clear(n_minus_three);
        mpz_clear(y);
        mpz_clear(j);
        mpz_clear(s_minus_one);
        mpz_clear(two);
        return true;
    }

    mpz_mod_ui(remainder, r, 2);
    while (mpz_cmp_ui(remainder, 0) == 0) {
        mpz_add_ui(s, s, 1);
        mpz_div_ui(r, r, 2);
        mpz_mod_ui(remainder, r, 2);
    }

    for (uint64_t i = 0; i < iters; i++) {
        mpz_urandomm(random_generated, state, n_minus_three);
        mpz_add_ui(random_generated, random_generated, 2);

        pow_mod(y, random_generated, r, n);
        if (mpz_cmp_ui(y, 1) != 0 && mpz_cmp(y, n_minus_one) != 0) {
            mpz_set_ui(j, 1);

            mpz_sub_ui(s_minus_one, s, 1);
            while (mpz_cmp(j, s_minus_one) <= 0 && mpz_cmp(y, n_minus_one) != 0) {
                pow_mod(y, y, two, n);
                if (mpz_cmp_ui(y, 1) == 0) {
                    mpz_clear(remainder);
                    mpz_clear(s);
                    mpz_clear(r);
                    mpz_clear(n_minus_one);
                    mpz_clear(random_generated);
                    mpz_clear(n_minus_three);
                    mpz_clear(y);
                    mpz_clear(j);
                    mpz_clear(s_minus_one);
                    mpz_clear(two);
                    return false;
                }
                mpz_add_ui(j, j, 1);
            }
            if (mpz_cmp(y, n_minus_one) != 0) {
                mpz_clear(remainder);
                mpz_clear(s);
                mpz_clear(r);
                mpz_clear(n_minus_one);
                mpz_clear(random_generated);
                mpz_clear(n_minus_three);
                mpz_clear(y);
                mpz_clear(j);
                mpz_clear(s_minus_one);
                mpz_clear(two);
                return false;
            }
        }
    }
    mpz_clear(remainder);
    mpz_clear(s);
    mpz_clear(r);
    mpz_clear(n_minus_one);
    mpz_clear(random_generated);
    mpz_clear(n_minus_three);
    mpz_clear(y);
    mpz_clear(j);
    mpz_clear(s_minus_one);
    mpz_clear(two);
    return true;
}

// This function generates a new prime number stored in p.
// This function takes in as parameters mpz_t p which is where we will store the generated prime, mpz_t bits which
// is the minimum bits long the prime generated has to be, and mpz_t iters which is the number of iterations which
// is what is_prime() will be using when called.
void make_prime(mpz_t p, uint64_t bits, uint64_t iters) {
    do {
        mpz_urandomb(p, state, bits + 1);
    } while (is_prime(p, iters) == false || mpz_sizeinbase(p, 2) < bits + 1);
}

// This function computes the greatest common divisor of a and b, storing the value of the computed
// divisor in d.
// This function takes in as parameters mpz_t d which is where the gcd of a and b is going to be stored,
// mpz_t a, and mpz_t b.
void gcd(mpz_t d, mpz_t a, mpz_t b) {
    mpz_t a_temp;
    mpz_init(a_temp);
    mpz_set(a_temp, a);
    mpz_t b_temp;
    mpz_init(b_temp);
    mpz_set(b_temp, b);
    while (mpz_cmp_ui(b_temp, 0) != 0) {
        mpz_set(d, b_temp);
        mpz_mmod(b_temp, a_temp, b_temp);
        mpz_set(a_temp, d);
    }
    mpz_set(d, a_temp);
    mpz_clear(a_temp);
    mpz_clear(b_temp);
}

// This function computes the inverse i of a modulo n.
// This function takes in as parameters mpz_t i which is where the modulo inverse will be stored, mpz_t a, and mpz_t n.
void mod_inverse(mpz_t i, mpz_t a, mpz_t n) {
    mpz_t r;
    mpz_init(r);
    mpz_t r_prime;
    mpz_init(r_prime);
    mpz_t t;
    mpz_init(t);
    mpz_t t_prime;
    mpz_init(t_prime);
    mpz_t q;
    mpz_init(q);
    mpz_t temp;
    mpz_init(temp);

    mpz_set(r, n);
    mpz_set(r_prime, a);
    mpz_set_ui(t, 0);
    mpz_set_ui(t_prime, 1);

    while (mpz_cmp_ui(r_prime, 0) != 0) {
        mpz_div(q, r, r_prime);

        mpz_set(temp, r);
        mpz_set(r, r_prime);
        mpz_mul(r_prime, q, r_prime);
        mpz_sub(r_prime, temp, r_prime);

        mpz_set(temp, t);
        mpz_set(t, t_prime);
        mpz_mul(t_prime, q, t_prime);
        mpz_sub(t_prime, temp, t_prime);
    }

    if (mpz_cmp_ui(r, 1) > 0) {
        mpz_set_ui(i, 0);
    } else {
        if (mpz_cmp_ui(t, 0) < 0) {
            mpz_add(t, t, n);
        }
        mpz_set(i, t);
    }
    mpz_clear(r);
    mpz_clear(r_prime);
    mpz_clear(t);
    mpz_clear(t_prime);
    mpz_clear(q);
    mpz_clear(temp);
}
