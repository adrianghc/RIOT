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
#include <thread.h>
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

#ifdef BOARD_NATIVE
#define SHOW_PROGRESS   1
#endif

#ifndef BOARD_NATIVE
#define SHOW_PROGRESS   0
#endif

/* Stack size for the progress printing thread */
char prog_thread_stack[THREAD_STACKSIZE_MAIN];

/* Number of iterations */
const int num_iterations = 1e5;

/* Digest length in bits */
const uint16_t hashbitlen = 256;
/* Delimited suffix for Keccak input padding */
const unsigned char keccak_delimitedSuffix = '\1';

/* Array with the lengths of the messages to be hashed */
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
 * The string is cut off at a given precision after the decimal point. If applicable and configured, the last digit is rounded up.
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
void get_floatstring(char* buf, size_t buf_size, int64_t dividend, int64_t divisor, uint8_t precision, uint8_t pre_precision, uint8_t round) {

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
        if ((!is_negative && buf[0] == '0' && buf[1] == '0') || (is_negative && buf[1] == '0' && buf[2] == '0')) {
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

#ifdef SHOW_PROGRESS

/* This thread prints the current benchmarking progress (i.e. the number of iterations finished) */
/* Native board only */
void *prog_thread(void *arg)
{
    uint32_t *i = arg;
    msg_t msg;

    while (1) {
        xtimer_sleep(1);
        msg_try_receive(&msg);
        if (msg.content.value == 1) {
            msg.content.value = 0;
            printf("\n");
            thread_sleep();
        } else if (msg.content.value == 2) {
            printf("\n");
            return NULL;
        } else {
            printf("Progress: %"PRIu32"\r", *i);
        }
    }
}

#endif

int main(void) {

    printf("\n\nMeasure performance of SHA256 and Keccak in ticks needed to calculate %d hash operations and in hash operations per tick.\n\n", num_iterations);

    /* Initialize */
    int32_t it_counter = 0;
    xtimer_ticks64_t start_ticks;
    xtimer_ticks64_t end_ticks;
    uint64_t ticks_dif;
    char ticks_buf[32];

    /* This thread prints the current benchmarking progress (i.e. the number of iterations finished) */
    /* Native board only */
    kernel_pid_t prog_thread_pid = thread_create(prog_thread_stack, sizeof(prog_thread_stack),
                                    THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_SLEEPING,
                                    prog_thread, &it_counter, "prog_thread");
    msg_t msg;

    /* Iterate through all desired string lengths */
    for (uint32_t k=0; k<sizeof(databytelens)/sizeof(databytelens[0]); k++) {

        size_t databytelen = databytelens[k];

        /* Generate random string */
        printf("\nGenerating random string of length %d.\n\n", databytelen);
        random_init(0x33799f);
        char* datastring = malloc(databytelen);
        if (datastring == NULL) {
            printf("\nNot enough memory for further benchmarks.\n\n");
            return 0;
        }
        for (uint32_t l=0; l<databytelen; l++) {
            datastring[l] = random_uint32_range(0x00, 0xff);
        }
        BitSequence* data = (unsigned char*) datastring;

        /* Measure performance of SHA256 */
        printf("Measure performance of SHA256.\n");
        sha256_context_t ctx;
        char sha256Hashval[hashbitlen/8];
        it_counter = 0;
        if (SHOW_PROGRESS) {
            thread_wakeup(prog_thread_pid);
        }
        start_ticks = xtimer_now64();
        for (; it_counter<num_iterations; it_counter++) {
            sha256_hash(&ctx, datastring, databytelen, sha256Hashval);
        }
        end_ticks = xtimer_now64();
        if (SHOW_PROGRESS) {
            msg.content.value = 1; // Ask progress printing thread to sleep
            msg_try_send(&msg, prog_thread_pid);
        }
        ticks_dif = (uint64_t) (end_ticks.ticks64 - start_ticks.ticks64);
        get_floatstring(ticks_buf, 32, num_iterations, ticks_dif, 8, 5, 1);
        printf("Performance of SHA256: %d hash operations in %u ticks (%s hash operations per tick).\n\n", num_iterations, (unsigned int) ticks_dif, ticks_buf);
        
        /* Measure performance of Keccak */
        printf("Measure performance of Keccak.\n");
        Keccak_HashInstance keccakHashInstance;
        BitSequence keccakHashval[hashbitlen/8];
        int keccak_rates[4];

        /* Rate for benchmark with c=256 for an equivalent security level to SHA-256 of 128 bits */
        keccak_rates[0] = 800-256;

        /* Rate for benchmark with c=512 for the landmark security level of 256 bits */
        keccak_rates[1] = 800-512;
        
        /* Calculate rate for benchmark normalized around the number of full state transformations (regardless of state size) */
        keccak_rates[2] = 8 * (hashbitlen/8 + (hashbitlen*hashbitlen/64)/databytelen);
        keccak_rates[2] += (8 - keccak_rates[0] % 8) % 8;

        /* Calculate rate for benchmark normalized around the state size */
        keccak_rates[3] = 100 + 100 * (hashbitlen/8) / databytelen;
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
            it_counter = 0;
            if (SHOW_PROGRESS) {
                thread_wakeup(prog_thread_pid);
            }
            start_ticks = xtimer_now64();
            for (; it_counter<num_iterations; it_counter++) {
                keccak_hash(&keccakHashInstance, data, 8*databytelen, keccakHashval, keccak_rates[j], 800-keccak_rates[j]);
            }
            end_ticks = xtimer_now64();
            if (SHOW_PROGRESS) {
                msg.content.value = 1; // Ask progress printing thread to sleep
                msg_try_send(&msg, prog_thread_pid);
            }
            ticks_dif = (uint64_t) (end_ticks.ticks64 - start_ticks.ticks64);
            get_floatstring(ticks_buf, 32, num_iterations, ticks_dif, 8, 5, 1);
            printf("Performance of Keccak for r=%d and c=%d: %d hash operations in %u ticks (%s hash operations per tick).\n", 
                keccak_rates[j], 800-keccak_rates[j], num_iterations, (unsigned int) ticks_dif, ticks_buf);
        }

        free(datastring);

    }

    printf("\n\nAll benchmarks finished!\n\n");
    if (SHOW_PROGRESS) {
        msg.content.value = 2; // Ask progress printing thread to terminate
        msg_send(&msg, prog_thread_pid);
    }

    return 0;
    
}
