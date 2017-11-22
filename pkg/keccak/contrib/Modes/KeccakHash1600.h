/*

Implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer, hereby
denoted as "the implementer".

For more information, feedback or questions, please refer to our websites:
http://keccak.noekeon.org/
http://keyak.noekeon.org/
http://ketje.noekeon.org/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>
*/

#ifndef KECCAKHASH1600_H
#define KECCAKHASH1600_H

#define KeccakP200_excluded
#define KeccakP400_excluded

#ifndef KeccakP1600_excluded

#include "KeccakHash.h"

#define Hash1600Return  HashReturn
#define Keccak1600_HashInstance Keccak_HashInstance

/**
  * Function to initialize the Keccak[r, c] sponge function instance used in sequential hashing mode.
  * @param  hashInstance    Pointer to the hash instance to be initialized.
  * @param  rate        The value of the rate r.
  * @param  capacity    The value of the capacity c.
  * @param  hashbitlen  The desired number of output bits,
  *                     or 0 for an arbitrarily-long output.
  * @param  delimitedSuffix Bits that will be automatically appended to the end
  *                         of the input message, as in domain separation.
  *                         This is a byte containing from 0 to 7 bits
  *                         formatted like the @a delimitedData parameter of
  *                         the Keccak_SpongeAbsorbLastFewBits() function.
  * @pre    One must have r+c=1600 and the rate a multiple of 8 bits in this implementation.
  * @return SUCCESS if successful, FAIL otherwise.
  */
#define Keccak1600_HashInitialize(hashInstance, rate, capacity, hashbitlen, delimitedSuffix)  Keccak_HashInitialize(hashInstance, rate, capacity, hashbitlen, delimitedSuffix)

/** Function to initialize a SHAKE128 instance as specified in the FIPS 202 standard.
  * @param  hashInstance  Pointer to the hash instance to be initialized.
  */
static inline void SHAKE128_initialize(Keccak1600_HashInstance *hashInstance) {
    Keccak1600_HashInitialize(hashInstance, 1344, 256, 0, 0x1F);
}

/** Function to initialize a SHAKE256 instance as specified in the FIPS 202 standard.
  * @param  hashInstance  Pointer to the hash instance to be initialized.
  */
static inline void SHAKE256_initialize(Keccak1600_HashInstance *hashInstance) {
    Keccak1600_HashInitialize(hashInstance, 1088, 512, 0, 0x1F);
}

/** Function to initialize a Keccak-1600 instance for hashing with a security level of 128 bits.
  * @param  hashInstance  Pointer to the hash instance to be initialized.
  */
static inline void SHA3_128_initialize(Keccak1600_HashInstance *hashInstance) {
    Keccak1600_HashInitialize(hashInstance, 1344, 256, 128, 0x06);
}

/** Function to initialize a SHA3-224 instance as specified in the FIPS 202 standard.
  * @param  hashInstance  Pointer to the hash instance to be initialized.
  */
static inline void SHA3_224_initialize(Keccak1600_HashInstance *hashInstance) {
    Keccak1600_HashInitialize(hashInstance, 1152, 448, 224, 0x06);
}

/** Function to initialize a SHA3-256 instance as specified in the FIPS 202 standard.
  * @param  hashInstance  Pointer to the hash instance to be initialized.
  */
static inline void SHA3_256_initialize(Keccak1600_HashInstance *hashInstance) {
    Keccak1600_HashInitialize(hashInstance, 1088, 512, 256, 0x06);
}

/** Function to initialize a SHA3-384 instance as specified in the FIPS 202 standard.
  * @param  hashInstance  Pointer to the hash instance to be initialized.
  */
static inline void SHA3_384_initialize(Keccak1600_HashInstance *hashInstance) {
    Keccak1600_HashInitialize(hashInstance, 832, 768, 384, 0x06);
}

/** Function to initialize a SHA3-384 instance as specified in the FIPS 202 standard.
  * @param  hashInstance  Pointer to the hash instance to be initialized.
  */
static inline void SHA3_512_initialize(Keccak1600_HashInstance *hashInstance) {
    Keccak1600_HashInitialize(hashInstance, 576, 1024, 512, 0x06);
}

/**
  * Function to give input data to be absorbed.
  * @param  hashInstance    Pointer to the hash instance initialized by Keccak_HashInitialize().
  * @param  data        Pointer to the input data.
  *                     When @a databitLen is not a multiple of 8, the last bits of data must be
  *                     in the least significant bits of the last byte (little-endian convention).
  * @param  databitLen  The number of input bits provided in the input data.
  * @pre    In the previous call to Keccak_HashUpdate(), databitlen was a multiple of 8.
  * @return SUCCESS if successful, FAIL otherwise.
  */
#define Keccak1600_HashUpdate(hashInstance, data, databitlen) Keccak_HashUpdate(hashInstance, data, databitlen)

/**
  * Function to call after all input blocks have been input and to get
  * output bits if the length was specified when calling Keccak_HashInitialize().
  * @param  hashInstance    Pointer to the hash instance initialized by Keccak_HashInitialize().
  * If @a hashbitlen was not 0 in the call to Keccak_HashInitialize(), the number of
  *     output bits is equal to @a hashbitlen.
  * If @a hashbitlen was 0 in the call to Keccak_HashInitialize(), the output bits
  *     must be extracted using the Keccak_HashSqueeze() function.
  * @param  hashval     Pointer to the buffer where to store the output data.
  * @return SUCCESS if successful, FAIL otherwise.
  */
#define Keccak1600_HashFinal(hashInstance, hashval) Keccak_HashFinal(hashInstance, hashval)

 /**
  * Function to squeeze output data.
  * @param  hashInstance    Pointer to the hash instance initialized by Keccak_HashInitialize().
  * @param  data        Pointer to the buffer where to store the output data.
  * @param  databitlen  The number of output bits desired (must be a multiple of 8).
  * @pre    Keccak_HashFinal() must have been already called.
  * @pre    @a databitlen is a multiple of 8.
  * @return SUCCESS if successful, FAIL otherwise.
  */
#define Keccak1600_HashSqueeze(hashInstance, data, databitlen)  Keccak_HashSqueeze(hashInstance, data, databitlen)

#endif

#endif
