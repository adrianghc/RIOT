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

#include <string.h>
#include "KeccakHash800.h"

/* ---------------------------------------------------------------- */

Hash800Return Keccak800_HashInitialize(Keccak800_HashInstance *instance, unsigned int rate, unsigned int capacity, unsigned int hashbitlen, unsigned char delimitedSuffix)
{
    Hash800Return result;

    if (delimitedSuffix == 0) {
        return FAIL_800;
    }
    result = (Hash800Return)KeccakWidth800_SpongeInitialize(&instance->sponge, rate, capacity);
    if (result != SUCCESS_800) {
        return result;
    }
    instance->fixedOutputLength = hashbitlen;
    instance->delimitedSuffix = delimitedSuffix;
    return SUCCESS_800;
}

/* ---------------------------------------------------------------- */

Hash800Return Keccak800_HashUpdate(Keccak800_HashInstance *instance, const BitSequence *data, BitLength databitlen)
{
    if ((databitlen % 8) == 0) {
        return (Hash800Return)KeccakWidth800_SpongeAbsorb(&instance->sponge, data, databitlen/8);
    } else {
        Hash800Return ret = (Hash800Return)KeccakWidth800_SpongeAbsorb(&instance->sponge, data, databitlen/8);
        if (ret == SUCCESS_800) {
            /* The last partial byte is assumed to be aligned on the least significant bits */
            unsigned char lastByte = data[databitlen/8];
            /* Concatenate the last few bits provided here with those of the suffix */
            unsigned short delimitedLastBytes = (unsigned short)((unsigned short)lastByte | ((unsigned short)instance->delimitedSuffix << (databitlen % 8)));
            if ((delimitedLastBytes & 0xFF00) == 0x0000) {
                instance->delimitedSuffix = delimitedLastBytes & 0xFF;
            }
            else {
                unsigned char oneByte[1];
                oneByte[0] = delimitedLastBytes & 0xFF;
                ret = (Hash800Return)KeccakWidth800_SpongeAbsorb(&instance->sponge, oneByte, 1);
                instance->delimitedSuffix = (delimitedLastBytes >> 8) & 0xFF;
            }
        }
        return ret;
    }
}

/* ---------------------------------------------------------------- */

Hash800Return Keccak800_HashFinal(Keccak800_HashInstance *instance, BitSequence *hashval)
{
    Hash800Return ret = (Hash800Return)KeccakWidth800_SpongeAbsorbLastFewBits(&instance->sponge, instance->delimitedSuffix);
    if (ret == SUCCESS_800) {
        return (Hash800Return)KeccakWidth800_SpongeSqueeze(&instance->sponge, hashval, instance->fixedOutputLength/8);
    } else {
        return ret;
    }
}

/* ---------------------------------------------------------------- */

Hash800Return Keccak800_HashSqueeze(Keccak800_HashInstance *instance, BitSequence *data, BitLength databitlen)
{
    if ((databitlen % 8) != 0) {
        return FAIL_800;
    }
    return (Hash800Return)KeccakWidth800_SpongeSqueeze(&instance->sponge, data, databitlen/8);
}
