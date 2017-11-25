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

#include "keccak800.h"
#include "keccak1600.h"
#include "embUnit.h"

const char datastring[] = "0123456789";
const bit_sequence* data = (unsigned char*) datastring;

const char hashvalstring800[] =
            "a6305bbe48f1f8d2c58dfd9731974fe85321c09cba8a944b0635a9ba07443324";

const char hashvalstring1600[] =
            "8f8eaad16cbf8722a2165b660d47fcfd8496a41c611da758f3bb70f809f01ee3";

static void test_keccak800(void)
{
    /* Initialize */
    keccak800hash_instance hash800Instance;
    bit_sequence hashval800[32];

    /* Testing hash initialization */
    keccak800hash_256_initialize(&hash800Instance);

    /* Testing hash update */
    hash_return return_update = keccak800hash_update(&hash800Instance, data, 80);
    TEST_ASSERT_EQUAL_INT(0, return_update);

    /* Testing hash finalization */
    hash_return return_final = keccak800hash_final(&hash800Instance, hashval800);
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
    /* Initialize */
    keccak1600hash_instance hash1600Instance;
    bit_sequence hashval1600[32];

    /* Testing hash initialization */
    sha3_256_initialize(&hash1600Instance);

    /* Testing hash update */
    hash_return return_update = keccak1600hash_update(&hash1600Instance, data, 80);
    TEST_ASSERT_EQUAL_INT(0, return_update);

    /* Testing hash finalization */
    hash_return return_final = keccak1600hash_final(&hash1600Instance, hashval1600);
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

    EMB_UNIT_TESTCALLER(keccak_tests, NULL, NULL, fixtures);
    return (Test*)&keccak_tests;
}
