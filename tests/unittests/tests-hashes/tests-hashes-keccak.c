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

#include "KeccakHash800.h"
#include "KeccakHash1600.h"
#include "embUnit.h"

Keccak800Hash_instance* hash800Instance;
Keccak1600Hash_instance* hash1600Instance;

const BitLength databitlen = 80;
const char datastring[] = "0123456789";
const BitSequence* data = (unsigned char*) datastring;

const char hashvalstring800[] =
            "a6305bbe48f1f8d2c58dfd9731974fe85321c09cba8a944b0635a9ba07443324";
BitSequence* hashval800;

const char hashvalstring1600[] =
            "8f8eaad16cbf8722a2165b660d47fcfd8496a41c611da758f3bb70f809f01ee3";
BitSequence* hashval1600;

static void setUp(void)
{
    /* Initialize */
    hash800Instance = malloc(sizeof(Keccak800Hash_instance));
    hashval800 = malloc(32);

    hash1600Instance = malloc(sizeof(Keccak1600Hash_instance));
    hashval1600 = malloc(32);
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
    Keccak800Hash_256_initialize(hash800Instance);

    /* Testing hash update */
    Hash800Return return_update = Keccak800Hash_update(hash800Instance, data, databitlen);
    TEST_ASSERT_EQUAL_INT(0, return_update);

    /* Testing hash finalization */
    Hash800Return return_final = Keccak800Hash_final(hash800Instance, hashval800);
    TEST_ASSERT_EQUAL_INT(0, return_final);

    /* Comparing digest with expected result */
    uint8_t eq = 1;
    char hashvalbuf[5];

    for (uint8_t i=0; i<32; i++) {
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
    SHA3_256_initialize(hash1600Instance);

    /* Testing hash update */
    Hash1600Return return_update = Keccak1600Hash_update(hash1600Instance, data, databitlen);
    TEST_ASSERT_EQUAL_INT(0, return_update);

    /* Testing hash finalization */
    Hash1600Return return_final = Keccak1600Hash_final(hash1600Instance, hashval1600);
    TEST_ASSERT_EQUAL_INT(0, return_final);

    /* Comparing digest with expected result */
    uint8_t eq = 1;
    char hashvalbuf[5];

    for (uint8_t i=0; i<32; i++) {
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
