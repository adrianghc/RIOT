/*
 * Copyright (C) 2017 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     tests
 * @{
 *
 * @file
 * @brief       Application for benchmarking the performance of Keccak-1600
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

#include "thread.h"
#include "xtimer.h"
#include "timex.h"
#include "random.h"
#include "keccak1600.h"


/* Stack size for the hashing threads */
char hash_thread_stack[2400];

/* Digest length in bits */
const uint16_t hashbitlen = 256;
/* Delimited suffix for Keccak input padding */
const unsigned char keccak_delimited_suffix = 0x06;

/* Array with the lengths of the messages to be hashed */
const bit_length databytelens[] = { 64, 100, 1024, 10240 };

typedef struct {
    keccak1600hash_instance* hash_instance;
    bit_sequence* data;
    bit_length databitlen;
    bit_sequence* hashval;
    int rate;
} keccak1600_struct;

void *keccak1600_hash(void *args) {
    keccak1600_struct *keccak1600_args = args;

    keccak1600hash_initialize(keccak1600_args->hash_instance, keccak1600_args->rate, 1600-keccak1600_args->rate,
                            hashbitlen, keccak_delimited_suffix);
    keccak1600hash_update(keccak1600_args->hash_instance, keccak1600_args->data, keccak1600_args->databitlen);
    keccak1600hash_final(keccak1600_args->hash_instance, keccak1600_args->hashval);

    return NULL;
}

/*
 * Function to generate a string with the result of a division
 * without using floating point arithmetic.
 * The string is cut off at a given precision after the decimal point.
 * If applicable and configured, the last digit is rounded up.
 * 
 * @param[out]  buf             Pointer to the buffer for the string to be generated.
 * @param[in]   buf_size        The size of the buffer.
 * @param[in]   dividend        The dividend.
 * @param[in]   divisor         The divisor.
 * @param[in]   precision       The maximum number of digits after the decimal point.
 * @param[in]   pre_precision   The maximum numer of digits before the decimal point.
 *                              Exception: When a number only containing the digit 9 is rounded up.
 * @param[in]   round           0 if the last digit is to be rounded up if applicable,
 *                              1 otherwise.
 */
void get_floatstring(char* buf, size_t buf_size, int64_t dividend, int64_t divisor,
                        uint8_t precision, uint8_t pre_precision, uint8_t round) {

    /* Initialize */
    uint8_t i = 0;
    uint8_t inc_i = 0;
    uint8_t buf_init = 0;
    uint8_t is_negative = 0;
    size_t len = 0;
    int64_t quot;
    char quot_chars[pre_precision+1];

    /* Handle divisor 0 */
    if (divisor == 0) {
        return;
    }

    /* Handle dividend 0 */
    if (dividend == 0) {
        strcpy(buf, "0");
        return;
    }

    /* Handle negative input */
    if ((dividend < 0 && divisor > 0) || (divisor < 0 && dividend > 0)) {
        is_negative = 1;
        dividend = abs(dividend);
        divisor = abs(divisor);
        strcpy(buf, "-");
        buf_init = 1;
        len += 1;
    }

    /* Generate the string */
    while (i<precision+1 && len<buf_size-1) {
        if (dividend < divisor) {
            if (!inc_i) {
                inc_i = 1;
                if (!is_negative && !buf_init) {
                    strcpy(buf, "0");
                    buf_init = 1;
                    len += 1;
                }
                else if (is_negative && buf[len-1] == '-') {
                    strncat(buf, "0", 1);
                    len += 1;
                }
                strncat(buf, ".", 1);
                len += 1;
            }
            dividend *= 10;
        }
        if (i == precision || len == buf_size-1) {
            if (buf[len-1] == '.') {
                buf[len-1] = '\0';
            }
            break;
        }
        quot = dividend / divisor;
        snprintf(quot_chars, pre_precision+1, "%d", (int) quot);
        if (i == 0 && !inc_i && !buf_init) {
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
            if (buf[j] == '.' || buf[j] == '-') {
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
        if ((!is_negative && buf[0] == '0' && buf[1] == '0')
            || (is_negative && buf[1] == '0' && buf[2] == '0')) {
                for (size_t k=len-1; k>0; k--) {
                    buf[k] = buf[k-1];
                }
                if (!is_negative) {
                    buf[0] = '1';
                } else {
                    buf[1] = '1';
                }
                buf[len] = '\0';
                if (buf[len-1] == '.') {
                    buf[len-1] = '\0';
                }
        }
    }
}

/* Benchmark for Keccak */
void keccak_benchmark(size_t databytelen, char* datastring, uint16_t p) {

    /* Initialize */
    xtimer_ticks64_t start_ticks;
    xtimer_ticks64_t end_ticks;
    uint64_t ticks_dif;
    char ratio_buf[32];

    kernel_pid_t hash_thread_pid = 0;
    uintptr_t hash_thread_first_stacksize;
    uintptr_t hash_thread_last_stacksize;

    bit_sequence* data = (unsigned char*) datastring;

    /* Measure performance of Keccak */
    printf("Measure performance of Keccak-%u.\n", p);
    bit_sequence keccak_hashval[hashbitlen/8];
    int keccak_rates[4];

    /* Rate for benchmark with c=256 for an equivalent security level to SHA-256 of 128 bits */
    keccak_rates[0] = p-256;

    /* Rate for benchmark with c=512 for the landmark security level of 256 bits */
    keccak_rates[1] = p-512;
    
    /*
        Calculate rate for benchmark normalized around the number of full state transformations
        (regardless of state size)
    */
    keccak_rates[2] = 8 * (hashbitlen/8 + (hashbitlen*hashbitlen/64)/databytelen);
    keccak_rates[2] += (8 - keccak_rates[0] % 8) % 8;

    /* Calculate rate for benchmark normalized around the state size */
    keccak_rates[3] = p/8 + p/8 * (hashbitlen/8) / databytelen;
    keccak_rates[3] += (8 - keccak_rates[3] % 8) % 8;

    for (uint32_t j=0; j<4; j++) {
        if (j==0) {
            printf("Benchmark with c=256 for an equivalent security level to SHA-256 of 128 bits:\n");
        } else if (j==1) {
            printf("Benchmark with c=512 for the landmark security level of 256 bits:\n");
        } else if (j==2) {
            printf("Benchmark normalized around the number of full state transformations (regardless of state size):\n");
        } else if (j==3) {
            printf("Benchmark normalized around the state size:\n");
        }

        keccak1600hash_instance keccak1600_hash_instance;
        keccak1600_struct args = {
                                    .hash_instance = &keccak1600_hash_instance,
                                    .data = data,
                                    .databitlen = 8*databytelen,
                                    .hashval = keccak_hashval,
                                    .rate = keccak_rates[j]
                                };
        hash_thread_pid = thread_create(hash_thread_stack, sizeof(hash_thread_stack),
                                    THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_STACKTEST | THREAD_CREATE_SLEEPING,
                                    keccak1600_hash, &args, "keccak1600");

        hash_thread_first_stacksize = thread_measure_stack_free(hash_thread_stack);
        start_ticks = xtimer_now64();
        thread_wakeup(hash_thread_pid);
        end_ticks = xtimer_now64();

        ticks_dif = (uint64_t) (end_ticks.ticks64 - start_ticks.ticks64);
        get_floatstring(ratio_buf, 32, ticks_dif, databytelen, 4, 5, 1);
        printf( "\tPerformance of Keccak-%u for r=%d and c=%d: %u ticks for one hash operation (%s ticks per hashed byte).\n",
                p, keccak_rates[j], p-keccak_rates[j], (unsigned int) ticks_dif, ratio_buf);
        hash_thread_last_stacksize = thread_measure_stack_free(hash_thread_stack);
        printf("\tStack size: %u bytes\n\n", hash_thread_first_stacksize - hash_thread_last_stacksize);
    }

}

int main(void) {

    printf( "\n\nMeasure performance of Keccak in ticks needed to calculate "
            "one hash operation and in hash operations per tick.\n\n");

    /* Iterate through all desired string lengths */
    for (uint32_t k=0; k<sizeof(databytelens)/sizeof(databytelens[0]); k++) {

        size_t databytelen = databytelens[k];

        /* Generate random string */
        printf("\nGenerating random string of length %d.\n\n", databytelen);
        random_init(0x33799f);
        char datastring[databytelen];
        for (uint32_t l=0; l<databytelen; l++) {
            datastring[l] = random_uint32_range(0x00, 0xff);
        }

        /* Measure performance of Keccak-1600 */
        keccak_benchmark(databytelen, datastring, 1600);

    }

    printf("\n\nAll benchmarks finished!\n\n");

    return 0;
    
}
