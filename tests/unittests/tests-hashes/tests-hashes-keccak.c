/*
 * Copyright (C) 2017 Adrian Herrmann <adrian.herrmann@fu-berlin.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     unittests
 * @{
 *
 * @file
 * @brief       Test cases for the Keccak hashing package
 *
 * @author      Adrian Herrmann <adrian.herrmann@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "KeccakHash800.h"
#include "embUnit.h"

#define KeccakP200_excluded
#define KeccakP400_excluded
#define KeccakP1600_excluded

Keccak_HashInstance* hashInstance;

const unsigned int rate = 544;
const unsigned int hashbitlen = 256;
const unsigned char delimitedSuffix = '\1';

const BitLength databitlen = 80;
const char datastring[] = "0123456789";
const BitSequence* data = (unsigned char*) datastring;

const char hashvalstring[] =
            "4c0ff0d8a1479dfe58fb0b55c7870e6c64e1c770fcd0bcb9fdc78d2570fb94a2";
BitSequence* hashval;

static void setUp(void)
{
    /* Initialize */
    hashInstance = malloc(sizeof(Keccak_HashInstance));
    hashval = malloc(hashbitlen / 8);
}

static void tearDown(void)
{
    /* Finalize */
    free(hashInstance);
    free(hashval);
}

static void test_keccak(void)
{
    /* Testing hash initialization */
    HashReturn return_init = Keccak_HashInitialize(hashInstance, rate, 800-rate,
                                                    hashbitlen, delimitedSuffix);
    TEST_ASSERT_EQUAL_INT(0, return_init);

    /* Testing hash update */
    HashReturn return_update = Keccak_HashUpdate(hashInstance, data, databitlen);
    TEST_ASSERT_EQUAL_INT(0, return_update);

    /* Testing hash finalization */
    HashReturn return_final = Keccak_HashFinal(hashInstance, hashval);
    TEST_ASSERT_EQUAL_INT(0, return_final);

    /* Comparing digest with expected result */
    uint8_t eq = 1;
    char hashvalbuf[2];

    for (uint8_t i=0; i<hashbitlen/8; i++) {
        sprintf(hashvalbuf, "%02x", hashval[i]);
        
        if (hashvalbuf[0] != hashvalstring[2*i] || hashvalbuf[1] != hashvalstring[2*i+1]) {
            eq = 0;
            break;
        }
    }

    TEST_ASSERT_EQUAL_INT(1, eq);
}

Test *tests_hashes_keccak_tests(void)
{
    EMB_UNIT_TESTFIXTURES(fixtures) {
        new_TestFixture(test_keccak)
    };

    EMB_UNIT_TESTCALLER(keccak_tests, setUp, tearDown, fixtures);
    return (Test*)&keccak_tests;
}
