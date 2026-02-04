#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdatomic.h>

#include "elf_parse.h"

#ifndef MVMM_MAX_VERSIONS
#define MVMM_MAX_VERSIONS 10
#endif

#ifndef ROTATE_EVERY
#define ROTATE_EVERY 1000
#endif

#define MVMM_PAGE_SIZE 4096

/*
 * Stato per pagina
 * Lo slot 0 all’inizio punta alla pagina reale della mmap
 */
typedef struct {
    _Atomic uint64_t last_ts_seen;                 // ultimo ts per cui ho cambiato versione (per farlo una sola volta)
    _Atomic uint32_t cur_slot;                     // slot corrente per load/store
    _Atomic uint64_t slot_ts[MVMM_MAX_VERSIONS];   // timestamp di ogni slot
    void    *slots[MVMM_MAX_VERSIONS];             // ptr pagina per ogni slot
} mvmm_page_state;

/*
 * Stato per regione (mmap)
 */
typedef struct {
    uintptr_t        base;     // base della regione mmap 
    size_t           len;      // lunghezza della regione
    size_t           npages;   // numero di pagine
    mvmm_page_state *pages;    // array di stati per pagina
} mvmm_region;

// Contatore globale delle store (ts = write_counter / ROTATE_EVERY)
static _Atomic uint64_t g_write_counter = 0;

/*
 * Lista dinamica delle regioni mmappate da tracciare.
 * È condivisa tra thread, perciò protetta da RW-lock.
 */
static mvmm_region *g_regions     = NULL;
static size_t       g_nregions    = 0;
static size_t       g_regions_cap = 0;
static pthread_rwlock_t g_regions_lock = PTHREAD_RWLOCK_INITIALIZER;

void the_patch(unsigned long mem, unsigned long regs) __attribute__((used));

/*
 * Alloca una pagina allineata a g_page_size.
 * Serve per creare le copie (versioni) delle pagine.
 */
static inline void *mvmm_alloc_page(void) {

    void *p = NULL;
    if (posix_memalign(&p, MVMM_PAGE_SIZE, MVMM_PAGE_SIZE) != 0) {
        return NULL;
    }
    return p;
}

/* Ritorna 1 se l'indirizzo a appartiene alla regione r */
static inline int mvmm_region_contains(const mvmm_region *r, uintptr_t a) {
    return (a >= r->base && a < r->base + r->len);
}

/*
 * Trova la regione che contiene l’indirizzo effettivo (EA)
 */
static inline mvmm_region *mvmm_find_region(uintptr_t ea) {

    pthread_rwlock_rdlock(&g_regions_lock);
    for (size_t i = 0; i < g_nregions; i++) {
        mvmm_region *r = &g_regions[i];
        if (mvmm_region_contains(r, ea)) {
            pthread_rwlock_unlock(&g_regions_lock);
            return r;
        }
    }
    pthread_rwlock_unlock(&g_regions_lock);
    return NULL;
}

/*
 * Restituisce il puntatore alla pagina “corrente” per quella pagina logica.
 * Deve essere sempre != NULL dopo l’inizializzazione.
 */
static inline void *mvmm_cur_page_ptr(const mvmm_region *r, size_t page_idx) {
    mvmm_page_state *ps = &r->pages[page_idx];
    uint32_t slot = atomic_load_explicit(&ps->cur_slot, memory_order_acquire);
    return ps->slots[slot];
}

/*
 * Calcola l’EA (effective address) usando i metadati MVM e lo snapshot dei registri.
 * Se ins->effective_operand_address è già valorizzato, lo usa direttamente.
 */
static inline uintptr_t mvm_get_ea_u(instruction_record *ins, unsigned long regs) {
    if (ins->effective_operand_address != 0x0) {
        return (uintptr_t)ins->effective_operand_address;
    }

    target_address *t = &ins->target;

    unsigned long A = 0, B = 0;
    if (t->base_index)  memcpy(&A, (void *)(regs + 8*(t->base_index-1)), 8);
    if (t->scale_index) memcpy(&B, (void *)(regs + 8*(t->scale_index-1)), 8);

    long disp = (long)t->displacement;
    long base = (long)A;
    long idx  = (long)B;
    long sc   = (long)t->scale;

    return (uintptr_t)(disp + base + idx * sc);
}

/*
 * Riscrive il registro base in modo che l’istruzione originale, quando riprende, acceda a ea_prime.
 *
 * MVP: supportiamo solo indirizzamenti del tipo:
 *   [base + displacement]
 * quindi:
 * - no RIP-relative
 * - base_index deve esserci
 * - scale_index deve essere 0 (niente index register)
 */
static inline int mvmm_rewrite_base_reg_for_ea(instruction_record *ins,
                                              unsigned long regs,
                                              uintptr_t ea,
                                              uintptr_t ea_prime)
{
    if (ins->rip_relative == 'y') return 0;

    target_address *t = &ins->target;
    if (t->base_index == 0) return 0;

    /* MVP: niente addressing complesso con index register */
    if (t->scale_index != 0) return 0;

    intptr_t delta = (intptr_t)(ea_prime - ea);
    if (delta == 0) return 1;

    /* Modifica in-place il valore del registro base nello snapshot regs */
    uint64_t base_val = 0;
    void *base_slot = (void *)(regs + 8*(t->base_index-1));
    memcpy(&base_val, base_slot, 8);

    base_val = (uint64_t)((intptr_t)base_val + delta);
    memcpy(base_slot, &base_val, 8);

    return 1;
}

/*
 * Registra una nuova regione mmap nella struttura globale.
 * È chiamata dal wrapper di mmap dopo la real_mmap.
 *
 * MVP: non gestiamo munmap/free delle regioni, quindi la lista cresce soltanto.
 */
static void mvmm_region_register(void *base, size_t len) {
    if (base == MAP_FAILED || base == NULL || len == 0) return;

    pthread_rwlock_wrlock(&g_regions_lock);

    /* Espandi l'array se serve */
    if (g_nregions == g_regions_cap) {
        size_t newcap = (g_regions_cap == 0) ? 4 : g_regions_cap * 2;
        mvmm_region *nr = (mvmm_region *)realloc(g_regions, newcap * sizeof(*nr));
        if (!nr) {
            pthread_rwlock_unlock(&g_regions_lock);
            fprintf(stderr, "[mvmm] realloc regions failed\n");
            abort();
        }
        g_regions = nr;
        g_regions_cap = newcap;
    }

    /* Inizializza la nuova regione */
    mvmm_region *r = &g_regions[g_nregions++];
    r->base = (uintptr_t)base;
    r->len  = len;
    r->npages = (len + MVMM_PAGE_SIZE - 1) / MVMM_PAGE_SIZE;

    r->pages = (mvmm_page_state *)calloc(r->npages, sizeof(*r->pages));
    if (!r->pages) {
        pthread_rwlock_unlock(&g_regions_lock);
        fprintf(stderr, "[mvmm] alloc pages failed\n");
        abort();
    }

    /*
     * Inizializza ogni pagina:
     * - slot 0 punta alla pagina reale della mmap ed è marcato con ts=0 (baseline)
     * - gli altri slot sono vuoti (ts=UINT64_MAX)
     * - cur_slot=0 significa che load/store inizialmente vedono la baseline
     */
    for (size_t i = 0; i < r->npages; i++) {
        mvmm_page_state *ps = &r->pages[i];

        atomic_store(&ps->last_ts_seen, UINT64_MAX);
        atomic_store(&ps->cur_slot, 0);

        ps->slots[0] = (void *)(r->base + i * MVMM_PAGE_SIZE);
        atomic_store(&ps->slot_ts[0], 0);

        for (uint32_t s = 1; s < MVMM_MAX_VERSIONS; s++) {
            ps->slots[s] = NULL;
            atomic_store(&ps->slot_ts[s], UINT64_MAX);
        }
    }

    pthread_rwlock_unlock(&g_regions_lock);

    fprintf(stderr,
            "[mvmm] region registered base=%p len=%zu pages=%zu page_size=%d (regions=%zu)\n",
            base, len, r->npages, MVMM_PAGE_SIZE, g_nregions);
}

void* __real_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);

void* __wrap_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    void *p = __real_mmap(addr, length, prot, flags, fd, offset);
    if (p != MAP_FAILED) {
        mvmm_region_register(p, length);
    }
    return p;
}

/*
 * Traduce l'indirizzo effettivo ea verso la versione corrente della pagina.
 *
 * Se is_store=1:
 * - calcola un timestamp MVP (wc/ROTATE_EVERY)
 * - alla prima store della pagina per quel ts, crea una nuova versione (COW)
 * - pubblica il nuovo slot come cur_slot
 *
 * Se is_store=0:
 * - non crea versioni, ma traduce verso cur_slot corrente.
 */
static inline uintptr_t mvmm_translate_ea(mvmm_region *r,
                                         uintptr_t ea,
                                         int is_store)
{
    if (!r) return ea;

    uintptr_t page_base = ea & ~((uintptr_t)MVMM_PAGE_SIZE - 1);
    size_t page_idx = (size_t)((page_base - r->base) / MVMM_PAGE_SIZE);
    if (page_idx >= r->npages) return ea;

    mvmm_page_state *ps = &r->pages[page_idx];

    if (is_store) {
        /* Timestamp MVP */
        uint64_t wc = atomic_fetch_add_explicit(&g_write_counter, 1, memory_order_relaxed) + 1;
        uint64_t ts = wc / (uint64_t)ROTATE_EVERY;

        
         // 1 sola copy on write per pagina per ts
        uint64_t seen = atomic_load_explicit(&ps->last_ts_seen, memory_order_acquire);
        if (seen != ts) {
            if (atomic_compare_exchange_strong_explicit(&ps->last_ts_seen, &seen, ts,
                                                       memory_order_acq_rel, memory_order_acquire))
            {
                uint32_t cur  = atomic_load_explicit(&ps->cur_slot, memory_order_acquire);
                uint32_t next = (cur + 1u) % MVMM_MAX_VERSIONS;

                void *dst = mvmm_alloc_page();
                if (dst) {
                    void *src = ps->slots[cur];

                    /* Copia la versione corrente nello slot nuovo */
                    memcpy(dst, src, MVMM_PAGE_SIZE);

                    /*
                     * Pubblicazione:
                     * - slots[next] punta alla nuova pagina
                     * - slot_ts[next] memorizza il timestamp della versione
                     * - cur_slot diventa next, quindi da qui in poi load/store vedono la nuova versione
                     *
                     * Nota: overwrite senza free => leak controllato (MVP).
                     */
                    ps->slots[next] = dst;
                    atomic_store_explicit(&ps->slot_ts[next], ts, memory_order_release);
                    atomic_store_explicit(&ps->cur_slot, next, memory_order_release);

                    fprintf(stderr, "[mvmm] COW ts=%lu region=%p page=%zu slot=%u\n",
                            (unsigned long)ts, (void*)r->base, page_idx, next);
                } else {
                    // alloc fallita: last_ts_seen è già ts, quindi non ritentiamo per questo ts
                }
            }
        }
    }

    /* Traduci ea verso la pagina corrente (cur_slot) mantenendo l’offset dentro pagina */
    uintptr_t off = ea - page_base;
    void *curp = mvmm_cur_page_ptr(r, page_idx);
    if (!curp) return ea;
    return (uintptr_t)curp + off;
}

/*
 * Entry point chiamato da MVM prima della memoria load/store strumentata.
 * Qui:
 * - calcolo EA
 * - trovo la regione
 * - traduco EA verso la versione corrente (COW se store)
 * - riscrivo il registro base nello snapshot regs, così l’istruzione originale usa EA' quando riparte
 */
void the_patch(unsigned long mem, unsigned long regs) {
    instruction_record *ins = (instruction_record *)mem;
    if (!ins) return;

    /* gestiamo solo load e store */
    if (ins->type != 's' && ins->type != 'l') return;

    uintptr_t ea = mvm_get_ea_u(ins, regs);
    if (ea == 0) return;

    mvmm_region *r = mvmm_find_region(ea);
    if (!r) return;

    int is_store = (ins->type == 's');
    uintptr_t ea_prime = mvmm_translate_ea(r, ea, is_store);

    /* se l’indirizzamento è complesso, per ora saltiamo */
    if (!mvmm_rewrite_base_reg_for_ea(ins, regs, ea, ea_prime)) return;
}

// non usato
#define buffer user_defined_buffer
char buffer[1024];

void user_defined(instruction_record *actual_instruction, patch *actual_patch) {
    (void)actual_instruction;
    (void)actual_patch;
}
