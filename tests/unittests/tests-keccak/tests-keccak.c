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
 * @brief       keccak crypto library tests
 *
 * @author      Adrian Herrmann <adrian.herrmann@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>
#include <string.h>

#include "KeccakHash800.h"
#include "embUnit.h"
#include "tests-keccak.h"

#define KeccakP200_excluded
#define KeccakP400_excluded
#define KeccakP1600_excluded

Keccak_HashInstance hashInstance;

const unsigned int rate = 480;
const unsigned int capacity = 320;
const unsigned int hashbitlen = 256;
const unsigned char delimitedSuffix = '\0';

const BitLength databitlen = 10;
const char datastring[10] = "0123456789";
const BitSequence* data = (unsigned char*) datastring;

const char hashvalstring[32] = "";
BitSequence hashval[32];

static void setUp(void)
{
    /* Initialize */
}

static void tearDown(void)
{
    /* Finalize */
}

static void test_keccak(void)
{
    HashReturn return_init = Keccak_HashInitialize(&hashInstance, rate, capacity, hashbitlen, delimitedSuffix);
    TEST_ASSERT_EQUAL_INT(0, return_init);

    HashReturn return_update = Keccak_HashUpdate(&hashInstance, data, databitlen);
    TEST_ASSERT_EQUAL_INT(0, return_update);

    HashReturn return_final = Keccak_HashFinal(&hashInstance, hashval);
    TEST_ASSERT_EQUAL_INT(0, return_final);

    TEST_ASSERT_EQUAL_STRING((char*) hashvalstring, (char*) hashval);
}

Test *tests_keccak_all(void)
{
    EMB_UNIT_TESTFIXTURES(fixtures) {
        new_TestFixture(test_keccak)
    };

    EMB_UNIT_TESTCALLER(keccak_tests, setUp, tearDown, fixtures);
    return (Test*)&keccak_tests;
}

void tests_keccak(void)
{
    TESTS_RUN(tests_keccak_all());
}
