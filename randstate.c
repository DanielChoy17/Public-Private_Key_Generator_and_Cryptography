#include <stdint.h>
#include "randstate.h"
#include "gmp.h"

gmp_randstate_t state;

// This function initializes the global random state named state with a Mersenne Twister algorithm,
// using seed as the random seed.
// This function takes in a uint64_t named seed.
void randstate_init(uint64_t seed) {
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, seed);
}

// This function clears and frees all memory used by the initialized global random state named state.
void randstate_clear(void) {
    gmp_randclear(state);
}
