#include "xtimer.h"
#include "KeccakHash800.h"
#include "hashes/sha256.h"

#define KeccakP200_excluded
#define KeccakP400_excluded
#define KeccakP1600_excluded

const uint32_t num_iterations = 1000000;
const uint8_t num_keccak_measurements = 42;
const uint16_t keccak_rates[42] = 
        {32,64,96,128,160,192,224,
        256,288,320,352,384,416,448,
        480,512,528,544,560,576,592,
        608,624,640,656,672,680,688,
        696,704,712,720,728,736,744,
        752,760,768,776,784,792,800};

const uint16_t hashbitlen = 256;
const unsigned char keccak_delimitedSuffix = '\0';

const BitLength databitlen = 10;
const char datastring[10] = "0123456789";
const BitSequence* data = (unsigned char*) datastring;

void keccak_hash(Keccak_HashInstance* hashInstance, BitSequence* hashval, int rate, int capacity) {
    Keccak_HashInitialize(hashInstance, rate, capacity, hashbitlen, keccak_delimitedSuffix);
    Keccak_HashUpdate(hashInstance, data, databitlen);
    Keccak_HashFinal(hashInstance, hashval);
}

void sha256_hash(sha256_context_t* ctx, char* hashval) {
    sha256_init(ctx);
    sha256_update(ctx, data, databitlen);
    sha256_final(ctx, hashval);
}

int main(void) {

    printf("Measure performance of SHA256 and Keccak in hash operations per second. String to be hashed: %s (%d Byte length)\n\n\n", datastring, databitlen);

    xtimer_ticks32_t start_time;
    xtimer_ticks32_t end_time;
    double hash_res;

    /* Measure performance of SHA256 */
    sha256_context_t ctx;
    char sha256Hashval[32];
    start_time = xtimer_now();
    for (uint32_t i=0; i<num_iterations; i++) {
        sha256_hash(&ctx, sha256Hashval);
    }
    end_time = xtimer_now();
    hash_res = num_iterations / (end_time.ticks32 - start_time.ticks32);
    printf("Performance of SHA256: %f hash operations per second.\n\n", hash_res);
    
    /* Measure performance of Keccak */
    Keccak_HashInstance keccakHashInstance;
    BitSequence keccakHashval[32];
    for (uint8_t j=0; j<num_keccak_measurements; j++) {
        start_time = xtimer_now();
        for (uint32_t i=0; i<num_iterations; i++) {
            keccak_hash(&keccakHashInstance, keccakHashval, keccak_rates[j], 800-keccak_rates[j]);
        }
        end_time = xtimer_now();
        hash_res = num_iterations / (end_time.ticks32 - start_time.ticks32);
        printf("Performance of Keccak for r=%u and c=%u: %f hash operations per second.\n", keccak_rates[j], 800-keccak_rates[j], hash_res);
    }

    return 0;
    
}
