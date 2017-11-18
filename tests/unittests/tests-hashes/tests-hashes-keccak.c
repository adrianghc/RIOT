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
#include "KeccakHash.h"
#include "embUnit.h"

#define KeccakP200_excluded
#define KeccakP400_excluded

Keccak800_HashInstance* hash800Instance;
Keccak_HashInstance* hash1600Instance;

const unsigned int capacity = 256;
const unsigned int hashbitlen = 256;
const unsigned char delimitedSuffix = '\1';

const BitLength databitlen = 80;
const char datastring[] = "0123456789";
const BitSequence* data = (unsigned char*) datastring;

const char hashvalstring800[] =
            "4c0ff0d8a1479dfe58fb0b55c7870e6c64e1c770fcd0bcb9fdc78d2570fb94a2";
BitSequence* hashval800;

const char hashvalstring1600[] =
            "13dc3578c7c187ae2e72ceaae2341b3a5d58ea73a0fdbcd0efe9f52081172c5b";
BitSequence* hashval1600;

static void setUp(void)
{
    /* Initialize */
    hash800Instance = malloc(sizeof(Keccak800_HashInstance));
    hashval800 = malloc(hashbitlen / 8);

    hash1600Instance = malloc(sizeof(Keccak_HashInstance));
    hashval1600 = malloc(hashbitlen / 8);
}

static void tearDown(void)
{
    /* Finalize */
    free(hash800Instance);
    free(hashval800);

    free(hash1600Instance);
    free(hashval1600);
}

static void test_keccak800(void)
{
    /* Testing hash initialization */
    Hash800Return return_init = Keccak800_HashInitialize(hash800Instance, 800-capacity, capacity,
                                                    hashbitlen, delimitedSuffix);
    TEST_ASSERT_EQUAL_INT(0, return_init);

    /* Testing hash update */
    Hash800Return return_update = Keccak800_HashUpdate(hash800Instance, data, databitlen);
    TEST_ASSERT_EQUAL_INT(0, return_update);

    /* Testing hash finalization */
    Hash800Return return_final = Keccak800_HashFinal(hash800Instance, hashval800);
    TEST_ASSERT_EQUAL_INT(0, return_final);

    /* Comparing digest with expected result */
    uint8_t eq = 1;
    char hashvalbuf[2];

    for (uint8_t i=0; i<hashbitlen/8; i++) {
        sprintf(hashvalbuf, "%02x", hashval800[i]);
        
        if (hashvalbuf[0] != hashvalstring800[2*i] || hashvalbuf[1] != hashvalstring800[2*i+1]) {
            eq = 0;
            break;
        }
    }

    TEST_ASSERT_EQUAL_INT(1, eq);
}

static void test_keccak1600(void)
{
    /* Testing hash initialization */
    HashReturn return_init = Keccak_HashInitialize(hash1600Instance, 1600-capacity, capacity,
                                                    hashbitlen, delimitedSuffix);
    TEST_ASSERT_EQUAL_INT(0, return_init);

    /* Testing hash update */
    HashReturn return_update = Keccak_HashUpdate(hash1600Instance, data, databitlen);
    TEST_ASSERT_EQUAL_INT(0, return_update);

    /* Testing hash finalization */
    HashReturn return_final = Keccak_HashFinal(hash1600Instance, hashval1600);
    TEST_ASSERT_EQUAL_INT(0, return_final);

    /* Comparing digest with expected result */
    uint8_t eq = 1;
    char hashvalbuf[2];

    for (uint8_t i=0; i<hashbitlen/8; i++) {
        sprintf(hashvalbuf, "%02x", hashval1600[i]);
        
        if (hashvalbuf[0] != hashvalstring1600[2*i] || hashvalbuf[1] != hashvalstring1600[2*i+1]) {
            eq = 0;
            break;
        }
    }

    TEST_ASSERT_EQUAL_INT(1, eq);
}

Test *tests_hashes_keccak_tests(void)
{
    EMB_UNIT_TESTFIXTURES(fixtures) {
        new_TestFixture(test_keccak800),
        new_TestFixture(test_keccak1600)
    };

    EMB_UNIT_TESTCALLER(keccak_tests, setUp, tearDown, fixtures);
    return (Test*)&keccak_tests;
}
