/*
 * Copyright (C) 2017 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Example application for benchmarking the performance of SHA256 vs Keccak-800
 *
 * @author      Adrian Herrmann <adrian.herrmann@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <math.h>

#include "xtimer.h"
#include "timex.h"
#include "random.h"
#include "KeccakHash800.h"
#include "hashes/sha256.h"

#define KeccakP200_excluded
#define KeccakP400_excluded
#define KeccakP1600_excluded

const int num_iterations = 1e6;

const uint16_t hashbitlen = 256;
const unsigned char keccak_delimitedSuffix = '\1';

const BitLength databytelens[] = { 64, 100, 1024, 10240, 102400 };

void keccak_hash(Keccak_HashInstance* hashInstance, BitSequence* data, BitLength databitlen, BitSequence* hashval, int rate, int capacity) {
    Keccak_HashInitialize(hashInstance, rate, capacity, hashbitlen, keccak_delimitedSuffix);
    Keccak_HashUpdate(hashInstance, data, databitlen);
    Keccak_HashFinal(hashInstance, hashval);
}

void sha256_hash(sha256_context_t* ctx, char* data, size_t databitlen, char* hashval) {
    sha256_init(ctx);
    sha256_update(ctx, data, databitlen);
    sha256_final(ctx, hashval);
}

/*
 * Function to generate a string with the result of a division without using floating point arithmetic.
 * The string is cut off after a certain precision. If applicable and configured, the last digit is rounded up.
 * 
 * @param[out]  buf         Pointer to the buffer for the string to be generated.
 * @param[in]   buf_size    The size of the buffer.
 * @param[in]   dividend    The dividend.
 * @param[in]   divisor     The divisor.
 * @param[in]   precision   The maximum number of digits after the decimal point.
 * @param[in]   round       0 if the last digit is to be rounded up if applicable,
 *                          1 otherwise.
 */
void get_floatstring(char* buf, size_t buf_size, long dividend, long divisor, uint8_t precision, uint8_t pre_precision, uint8_t round) {

    /* Initialize */
    uint8_t i = 0;
    uint8_t inc_i = 0;
    uint8_t buf_init = 0;
    size_t len = 0;
    long quot;
    char quot_chars[pre_precision+1];

    /* Generate the string */
    while (i<precision+1 && len<buf_size-1) {
        if (dividend < divisor) {
            if (!inc_i) {
                inc_i = 1;
                if (!buf_init) {
                    strcpy(buf, "0");
                    len += 1;
                }
                strncat(buf, ".", 1);
                len += 1;
            }
            dividend *= 10;
        }
        if (i == precision) {
            break;
        }
        quot = dividend / divisor;
        snprintf(quot_chars, pre_precision+1, "%ld", quot);
        if (i == 0 && !inc_i) {
            strcpy(buf, quot_chars);
            buf_init = 1;
        } else {
            strncat(buf, quot_chars, pre_precision+1);
        }
        len += strlen(quot_chars);
        dividend -= divisor * quot;
        if (inc_i) {
            i++;
        }
    }
    if (len == buf_size-1 && dividend < divisor) {
        dividend *= 10;
    }
    buf[len] = '\0';

    /* End here if rounding is not desired */
    if (!round) {
        return;
    }

    /* Do the rounding */
    quot = dividend / divisor;
    if (quot >= 5) {
        for (int j=len-1; j>=0; j--) {
            if (buf[j] == '.') {
                continue;
            }
            if (buf[j] >= '9') {
                buf[j] = '0';
            } else {
                buf[j]++;
                break;
            }
        }
        /* Special case if a number that was rounded up only contained the digit 9 */
        if (buf[0] == '0' && buf[1] == '0') {
            for (size_t k=len-1; k>0; k--) {
                buf[k] = buf[k-1];
            }
            buf[0] = '1';
            buf[len] = '\0';
            if (buf[len-1] == '.') {
                buf[len-1] = '\0';
            }
        }
    }
}

int main(void) {

    printf("Measure performance of SHA256 and Keccak in ticks needed to calculate %d hash operations and in hash operations per tick.\n\n\n", num_iterations);

    xtimer_ticks64_t start_ticks;
    xtimer_ticks64_t end_ticks;
    long ticks_dif;
    char ticks_buf[32];

    /* Iterate through all desired string lengths */
    for (uint32_t k=0; k<sizeof(databytelens)/sizeof(databytelens[0]); k++) {

        size_t databytelen = databytelens[k];

        /* Generate random string */
        printf("Generating random string of length %d.\n\n", databytelen);
        random_init(0x33799f);
        char* datastring = malloc(databytelen);
        for (uint32_t l=0; l<databytelen; l++) {
            datastring[l] = random_uint32_range(0x00, 0xff);
        }
        BitSequence* data = (unsigned char*) datastring;

        /* Measure performance of SHA256 */
        printf("Measure performance of SHA256.\n");
        sha256_context_t ctx;
        char sha256Hashval[hashbitlen/8];
        start_ticks = xtimer_now64();
        for (int32_t i=0; i<num_iterations; i++) {
            sha256_hash(&ctx, datastring, databytelen, sha256Hashval);
        }
        end_ticks = xtimer_now64();
        ticks_dif = (long) (end_ticks.ticks64 - start_ticks.ticks64);
        get_floatstring(ticks_buf, 32, num_iterations, ticks_dif, 4, 5, 1);
        printf("Performance of SHA256: %d hash operations in %ld ticks (%s hash operations per tick).\n\n", num_iterations, ticks_dif, ticks_buf);
        
        /* Measure performance of Keccak */
        printf("Measure performance of Keccak.\n");
        Keccak_HashInstance keccakHashInstance;
        BitSequence keccakHashval[hashbitlen/8];
        int keccak_rates[2];
        
        /* Calculate rate for benchmark normalized around the number of full state transformations (regardless of state size) */
        keccak_rates[0] = 8 * (hashbitlen/8 + (hashbitlen*hashbitlen/64)/databytelen);
        keccak_rates[0] += (8 - keccak_rates[0] % 8) % 8;

        /* Calculate rate for benchmark normalized around the state size */
        keccak_rates[1] = 100 + 100 * (hashbitlen/8) / databytelen;
        keccak_rates[1] += (8 - keccak_rates[1] % 8) % 8;

        for (uint32_t j=0; j<2; j++) {
            if (j==0) {
                printf("Benchmark normalized around the number of full state transformations (regardless of state size):\n");
            } else if (j==1) {
                printf("Benchmark normalized around the state size:\n");
            }
            start_ticks = xtimer_now64();
            for (int32_t i=0; i<num_iterations; i++) {
                keccak_hash(&keccakHashInstance, data, 8*databytelen, keccakHashval, keccak_rates[j], 800-keccak_rates[j]);
            }
            end_ticks = xtimer_now64();
            ticks_dif = (long) (end_ticks.ticks64 - start_ticks.ticks64);
            get_floatstring(ticks_buf, 32, num_iterations, ticks_dif, 4, 5, 1);
            printf("Performance of Keccak for r=%d and c=%d: %d hash operations in %ld ticks (%s hash operations per tick).\n", 
                keccak_rates[j], 800-keccak_rates[j], num_iterations, ticks_dif, ticks_buf);
        }

        printf("\n");
        free(datastring);

    }

    return 0;
    
}
