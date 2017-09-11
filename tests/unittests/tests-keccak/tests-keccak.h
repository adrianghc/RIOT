/*
 * Copyright (C) 2017 Adrian Herrmann
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @addtogroup  unittests
 * @{
 *
 * @file
 * @brief       Unittests for the ``keccak`` package
 *
 * @author      Adrian Herrmann <adrian.herrmann@fu-berlin.de>
 */
#ifndef TESTS_TWEETKECCAK_H
#define TESTS_TWEETKECCAK_H

#include "KeccakHash800.h"
#include "embUnit/embUnit.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
*  @brief   The entry point of this test suite.
*/
void tests_keccak(void);

/**
 * @brief   Generates tests for keccak
 *
 * @return  embUnit tests if successful, NULL if not.
 */
Test *tests_keccak_tests(void);

#ifdef __cplusplus
}
#endif

#endif /* TESTS_TWEETNACL_H */
/** @} */
