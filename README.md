# Program Explanation

The purpose of this program is to create a key generator (keygen.c), an encryptor (encrypt.c), and a decryptor (decrypt.c). The keygen program will be in charge of key generation, producing RSA public and private key pairs. The encrypt program will encrypt files using a public key and the decrypt program will decrypt the encrypted files using the corresponding private key. In order to accomplish this, we will need to implement two libraries and a random state module that will be used in each of the programs. One of the libraries will hold functions relating to the mathematics behind RSA and the other library will contain implementations of routines for RSA. The random state module contains a single extern declaration to a global random state variable called state, and two functions: one to initialize the state and one to clear it.  


## Formatting

To format all the source code including header files:

...

$ make format

...


## Building 

To build this program run: 

...

$ make all

...


## Running

To run keygen.c:

$ ./keygen

The program accepts the following command-line options for keygen:

• -b: specifies the minimum bits needed for the public modulus n.

• -i: specifies the number of Miller-Rabin iterations for testing primes (default: 50).

• -n pbfile: specifies the public key file (default: rsa.pub).

• -d pvfile: specifies the private key file (default: rsa.priv).

• -s: specifies the random seed for the random state initialization (default: the seconds since the UNIX epoch, given by time(NULL)).

• -v: enables verbose output.

• -h: displays program synopsis and usage.

...

To run encrypt.c:

$ ./encrypt 

The program accepts the following command-line options for encrypt:

• -i: specifies the input file to encrypt (default: stdin).

• -o: specifies the output file to encrypt (default: stdout).

• -n: specifies the file containing the public key (default: rsa.pub).

• -v: enables verbose output.

• -h: displays program synopsis and usage.

...

To run decrypt.c:

$ ./decrypt

The program accepts the following command-line options for decrypt:

• -i: specifies the input file to decrypt (default: stdin).

• -o: specifies the output file to decrypt (default: stdout).

• -n: specifies the file containing the private key (default: rsa.priv).

• -v: enables verbose output.

• -h: displays program synopsis and usage.


## Cleaning

To remove all files that are compiler generated:

...

$ make clean

...
