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

#ifndef KECCAKHASH800_H
#define KECCAKHASH800_H

#define KeccakP200_excluded
#define KeccakP400_excluded

#ifndef KeccakP800_excluded

#include "KeccakSpongeWidth800.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _Keccak_BitTypes_
#define _Keccak_BitTypes_
typedef unsigned char BitSequence;

typedef size_t BitLength;
#endif

typedef enum { SUCCESS_800 = 0, FAIL_800 = 1, BAD_HASHLEN_800 = 2 } Hash800Return;

typedef struct {
    KeccakWidth800_SpongeInstance sponge;
    unsigned int fixedOutputLength;
    unsigned char delimitedSuffix;
} Keccak800Hash_instance;

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
  * @pre    One must have r+c=800 and the rate a multiple of 8 bits in this implementation.
  * @return SUCCESS if successful, FAIL otherwise.
  */
Hash800Return Keccak800Hash_initialize(Keccak800Hash_instance *hashInstance, unsigned int rate, unsigned int capacity, unsigned int hashbitlen, unsigned char delimitedSuffix);

/** Function to initialize a Keccak-800 instance for XOF with a security level of 128 bits.
  * @param  hashInstance  Pointer to the hash instance to be initialized.
  */
static inline void Keccak800XOF_128_initialize(Keccak800Hash_instance *hashInstance) {
    Keccak800Hash_initialize(hashInstance, 544, 256, 0, 0x1F);
}

/** Function to initialize a Keccak-800 instance for XOF with a security level of 256 bits.
  * @param  hashInstance  Pointer to the hash instance to be initialized.
  */
static inline void Keccak800XOF_256_initialize(Keccak800Hash_instance *hashInstance) {
    Keccak800Hash_initialize(hashInstance, 288, 512, 0, 0x1F);
}

/** Function to initialize a Keccak-800 instance for hashing with a security level of 128 bits.
  * @param  hashInstance  Pointer to the hash instance to be initialized.
  */
static inline void Keccak800Hash_128_initialize(Keccak800Hash_instance *hashInstance) {
    Keccak800Hash_initialize(hashInstance, 544, 256, 128, 0x06);
}

/** Function to initialize a Keccak-800 instance for hashing with a security level and output size of 224 bits.
  * @param  hashInstance  Pointer to the hash instance to be initialized.
  */
static inline void Keccak800Hash_224_initialize(Keccak800Hash_instance *hashInstance) {
    Keccak800Hash_initialize(hashInstance, 352, 448, 224, 0x06);
}

/** Function to initialize a Keccak-800 instance for hashing with a security level and output size of 256 bits.
  * @param  hashInstance  Pointer to the hash instance to be initialized.
  */
static inline void Keccak800Hash_256_initialize(Keccak800Hash_instance *hashInstance) {
    Keccak800Hash_initialize(hashInstance, 288, 512, 256, 0x06);
}

/** Function to initialize a Keccak-800 instance for hashing with a security level and output size of 384 bits.
  * @param  hashInstance  Pointer to the hash instance to be initialized.
  */
static inline void Keccak800Hash_384_initialize(Keccak800Hash_instance *hashInstance) {
    Keccak800Hash_initialize(hashInstance, 32, 768, 384, 0x06);
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
Hash800Return Keccak800Hash_update(Keccak800Hash_instance *hashInstance, const BitSequence *data, BitLength databitlen);

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
Hash800Return Keccak800Hash_final(Keccak800Hash_instance *hashInstance, BitSequence *hashval);

 /**
  * Function to squeeze output data.
  * @param  hashInstance    Pointer to the hash instance initialized by Keccak_HashInitialize().
  * @param  data        Pointer to the buffer where to store the output data.
  * @param  databitlen  The number of output bits desired (must be a multiple of 8).
  * @pre    Keccak_HashFinal() must have been already called.
  * @pre    @a databitlen is a multiple of 8.
  * @return SUCCESS if successful, FAIL otherwise.
  */
Hash800Return Keccak800Hash_squeeze(Keccak800Hash_instance *hashInstance, BitSequence *data, BitLength databitlen);

#endif

#ifdef __cplusplus
}
#endif

#endif /* KECCAKHASH800_H */
