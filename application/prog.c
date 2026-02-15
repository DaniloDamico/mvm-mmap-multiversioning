#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <sys/mman.h>
#include <unistd.h>

#define REGION_BYTES (32 * 1024 * 1024)   // 32 MB
#define ITERS 100000ULL
#define RUNS         30

static inline uint64_t nsec_now(void) {
    struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// Linear Congruential Generator per accessi pseudo-random
static inline uint64_t lcg_next(uint64_t x) {
    return x * 2862933555777941757ULL + 3037000493ULL;
}

/*
 * buf: memoria mmappata
 * len: lunghezza in bytes (multiplo di 8)
 * iters: quante iterazioni fare
 */
__attribute__((noinline)) // per evitare che il benchmark venga falsato
void function(uint8_t *buf, size_t len, uint64_t iters) {

    uint64_t *a = (uint64_t*)buf; // casto a 8B per evitare operazioni cross page
    const size_t n = len / sizeof(uint64_t);

    // calcolo il modulo
    const uint64_t mask = (uint64_t)n - 1;

    uint64_t state = 1; // inizio generatore

	 volatile uint64_t sink = 0; // Il sink serve a evitare che il compilatore elimini le operazioni di read/write come dead code

    for (uint64_t i = 0; i < iters; i++) {
        state = lcg_next(state);
        size_t idx = (size_t)(state & mask); // indice pseudo-random in [0, n-1]

        uint64_t v = a[idx];   // read
        v = (v ^ state) + 1;   // xor con lo stato
        a[idx] = v;            // write

		sink += v;   // impedisce ottimizzazioni aggressive
    }
}

int main(void) {


    // mmap region
    uint8_t *buf = mmap(NULL, (size_t)REGION_BYTES, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // butto il cold start atrimenti mi sporca i risultati
    function(buf, (size_t)REGION_BYTES, ITERS);

    uint64_t times[RUNS];

    for (int r = 0; r < RUNS; r++) {
        uint64_t t0 = nsec_now();
        function(buf, (size_t)REGION_BYTES, ITERS);
        uint64_t t1 = nsec_now();
        times[r] = t1 - t0;
        printf("run %d: %.3f ms\n", r, (double)times[r] / 1e6);
    }

    long double sum = 0;
    for (int r = 0; r < RUNS; r++) sum += (long double)times[r];
    long double mean = sum / (long double)RUNS;

    printf("mean: %.3f ms | %.2f ns/op\n",
           (double)mean / 1e6,
           (double)(mean / (long double)ITERS));

    return 0;
}