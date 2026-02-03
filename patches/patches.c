#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include "elf_parse.h"
#include <sys/mman.h>

#ifndef MVMM_MAX_VERSIONS
#define MVMM_MAX_VERSIONS 10
#endif

#ifndef ROTATE_EVERY
#define ROTATE_EVERY 1000
#endif

typedef struct {
    uint64_t ts[MVMM_MAX_VERSIONS];
    void    *snap[MVMM_MAX_VERSIONS];   // 4KB ciascuna
    uint32_t head;                      // prossima sottoregione
} mvmm_page_versions;

static mvmm_page_versions *g_versions = NULL; // g_versions[page] ring buffer delle snapshot di quella pagina
static uint64_t g_write_counter = 0;
static size_t g_page_size = 0;


void the_patch (unsigned long, unsigned long) __attribute__((used));

static uintptr_t g_base = 0;
static size_t    g_len  = 0;
static uint64_t *g_last_ts = NULL; // g_last_ts[page] ultimo timestamp in cui quella pagina è stata “versionata”
static size_t    g_npages  = 0;

void mvmm_region_register(void *base, size_t len) {
    // base della regione da tracciare
    g_base = (uintptr_t)base;
    g_len  = len;

    g_page_size = (size_t)getpagesize();
    size_t npages = (len + g_page_size - 1) / g_page_size;

    g_last_ts = (uint64_t *)calloc(npages, sizeof(*g_last_ts));

    if (!g_last_ts || !g_versions) {
     fprintf(stderr, "[mvmm] metadata alloc failed\n");
     abort();
    }

    g_versions = (mvmm_page_versions *)calloc(npages, sizeof(*g_versions));

    g_npages = npages;
}


static inline int mvmm_is_tracked_address(void *p) {
    uintptr_t a = (uintptr_t)p;
    return (g_base != 0 && a >= g_base && a < g_base + g_len);
}

void* __real_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);

void* __wrap_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    void *p = __real_mmap(addr, length, prot, flags, fd, offset);
    if (p != MAP_FAILED) {
        mvmm_region_register(p, length);
        // debug temporaneo:
        fprintf(stderr, "[mvmm] mmap %p len=%zu\n", p, length);
    }
    return p;
}

/**
 * Computes the effective address of a memory operand for a given instruction record and CPU register state.
 */
static inline unsigned long mvm_get_ea(instruction_record *instruction, unsigned long regs) {
    if (instruction->effective_operand_address != 0x0)
        return instruction->effective_operand_address;

    target_address *t = &instruction->target;

    unsigned long A = 0, B = 0;
    if (t->base_index)  memcpy(&A, (void *)(regs + 8*(t->base_index-1)), 8);
    if (t->scale_index) memcpy(&B, (void *)(regs + 8*(t->scale_index-1)), 8);

    return (unsigned long)((long)t->displacement + (long)A + (long)((long)B * (long)t->scale));
}

static inline void* mvmm_alloc_page(void) {
    void *p = NULL;
    if (posix_memalign(&p, g_page_size, g_page_size) != 0) return NULL;
    return p;
}

/**
 * implementa la logica di gestione delle versioni per una sottoregione di memoria, intercettando le operazioni di scrittura e creando, quando necessario, una nuova versione consistente della sottoregione stessa.”
 */
void mvmm_handle_store(void *addr) {
    // timestamp basato su contatore di store
    uint64_t wc = ++g_write_counter;
    uint64_t ts = wc / (uint64_t)ROTATE_EVERY;

    // calcola pagina base e indice pagina
    uintptr_t a = (uintptr_t)addr;
    uintptr_t page_base = a & ~((uintptr_t)g_page_size - 1);

    if (g_base == 0 || g_page_size == 0 || g_last_ts == NULL || g_versions == NULL) return;

    size_t page_idx = (size_t)((page_base - g_base) / g_page_size);
    if (page_idx >= g_npages) return;

    // snapshot solo alla prima write della pagina per questo ts
    if (g_last_ts[page_idx] == ts) return;

    void *copy = mvmm_alloc_page();
    if (!copy) return;

    memcpy(copy, (void*)page_base, g_page_size);

    mvmm_page_versions *pv = &g_versions[page_idx];
    uint32_t slot = pv->head % MVMM_MAX_VERSIONS;

    // overwrite: perdiamo il puntatore precedente => leak controllato (MVP)
    pv->snap[slot] = copy;
    pv->ts[slot]   = ts;
    pv->head++;

    g_last_ts[page_idx] = ts;

    // log
    fprintf(stderr, "[mvmm] snapshot ts=%lu page=%zu addr=%p slot=%u\n",
            (unsigned long)ts, page_idx, (void*)page_base, (unsigned)slot);
}




void the_patch(unsigned long mem, unsigned long regs) {
    instruction_record *ins = (instruction_record*) mem;

// TODO in futuro modificare anche le load, quando metteró il cambio di versione
    if (ins->type != 's') return;

    unsigned long ea = mvm_get_ea(ins, regs);
    if (ea == 0) return;

    if (!mvmm_is_tracked_address((void*)ea)) return;

    mvmm_handle_store((void*)ea);
}




//used_defined(...) is the real body of the user-defined instrumentation process, all the stuff you put here represents the actual execution path of an instrumented instruction
//given that you have the exact representation of the instruction to be instrumented, you can produce the
//block of ASM level instructions to be really used for istrumentation
//clearly any memory/register side effect is under the responsibility of the patch programme
//the instrumentation instructions whill be executed right after the original instruction to be instrumented

#define buffer user_defined_buffer//this avoids compile-time replication of the buffer symbol 
char buffer[1024];
//in this function you get the pointer to the metedata representaion of the instruction to be instrumented
//and the pointer to the buffer where the patch (namely the instrumenting instructions) can be placed
//simply eturning form this function with no management of the pointed areas menas that you are skipping
//the instrumentatn of this instruction

void user_defined(instruction_record * actual_instruction, patch * actual_patch){
}
