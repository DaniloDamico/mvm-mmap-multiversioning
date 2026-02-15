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

// ogni quante scritture fare rollback
#define MVMM_ROLLBACK_AT_WRITES 10000

#define MVMM_DEBUG 0

// se il flag é abilitato posso evitare di riallocare memoria ogni volta che faccio copy on write
// serve per il benchmark
#define SINGLE_THREAD 1

#if MVMM_DEBUG
#define MVMM_LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define MVMM_LOG(...) \
    do                \
    {                 \
    } while (0)
#endif

static _Atomic uint64_t g_last_rollback_wc = 0;

/*
 * Stato per pagina
 * Lo slot 0 all’inizio punta alla pagina reale della mmap
 */
typedef struct
{
    _Atomic uint64_t last_ts_seen;               // ultimo ts per cui ho cambiato versione (per farlo una sola volta)
    _Atomic uint32_t cur_slot;                   // slot corrente per load/store
    _Atomic uint64_t slot_ts[MVMM_MAX_VERSIONS]; // timestamp di ogni slot
    _Atomic(void *) slots[MVMM_MAX_VERSIONS];    // ptr pagina per ogni slot
} mvmm_page_state;

/*
 * Stato per regione (mmap)
 */
typedef struct
{
    uintptr_t base;         // base della regione mmap
    size_t len;             // lunghezza della regione
    size_t npages;          // numero di pagine
    mvmm_page_state *pages; // array di stati per pagina
} mvmm_region;

// Contatore globale delle store (ts = write_counter / ROTATE_EVERY)
static _Atomic uint64_t g_write_counter = 0;

/*
 * linked list delle regioni mmappate da tracciare.
 */
typedef struct mvmm_region_node
{
    mvmm_region r;
    struct mvmm_region_node *next;
} mvmm_region_node;

// Lista regioni registrate (una per mmap)
static mvmm_region_node *g_regions_head = NULL;

// lock tanti reader un writer
static pthread_rwlock_t g_regions_lock = PTHREAD_RWLOCK_INITIALIZER;

void the_patch(unsigned long mem, unsigned long regs) __attribute__((used));
static void mvmm_maybe_trigger_rollback(uint64_t wc_now) __attribute__((used));

/*
 * Alloca una pagina allineata a g_page_size
 *
 * posix_memalign per garantire l’allineamento, al contrario di malloc
 */
static inline void *mvmm_alloc_page(void)
{

    void *p = NULL;
    if (posix_memalign(&p, MVMM_PAGE_SIZE, MVMM_PAGE_SIZE) != 0)
    {
        return NULL;
    }
    return p;
}

/* Ritorna 1 se l'indirizzo a appartiene alla regione r */
static inline int mvmm_region_contains(const mvmm_region *r, uintptr_t a)
{
    return (a >= r->base && a < r->base + r->len);
}

/*
 * Trova la regione che contiene l’indirizzo effettivo
 */
static inline mvmm_region *mvmm_find_region(uintptr_t ea)
{

    pthread_rwlock_rdlock(&g_regions_lock); // lock in lettura

    for (mvmm_region_node *n = g_regions_head; n != NULL; n = n->next)
    {
        if (mvmm_region_contains(&n->r, ea))
        {
            pthread_rwlock_unlock(&g_regions_lock);
            return &n->r;
        }
    }

    pthread_rwlock_unlock(&g_regions_lock);
    return NULL;
}

/*
 * Restituisce il puntatore alla pagina corrente per quella pagina logica
 * param r: la regione trovata da mvmm_find_region
 * param page_idx: indice della pagina
 */
static inline void *mvmm_cur_page_ptr(const mvmm_region *r, size_t page_idx)
{
    mvmm_page_state *ps = &r->pages[page_idx];
    uint32_t slot = atomic_load_explicit(&ps->cur_slot, memory_order_acquire); // legge slot in modo atomico. memory_order_acquire garantisce che veda tutti gli eventi passati.
    return atomic_load_explicit(&ps->slots[slot], memory_order_acquire);
}

/*
 * Calcola l’EA usando i metadati MVM e lo snapshot dei registri.
 * Se ins->effective_operand_address è già valorizzato, lo usa direttamente.
 */
static inline uintptr_t mvm_get_ea_u(instruction_record *ins, unsigned long regs)
{
    if (ins->effective_operand_address != 0x0)
    {
        return (uintptr_t)ins->effective_operand_address;
    }

    target_address *t = &ins->target;

    // 8* perché i registri sono a 8 byte di distanza l’uno dall’altro
    // puntatore a registri (regs) + 8*(indice-1) per trovare quello giusto
    unsigned long A = 0, B = 0;
    if (t->base_index)
        memcpy(&A, (void *)(regs + 8 * (t->base_index - 1)), 8);
    if (t->scale_index)
        memcpy(&B, (void *)(regs + 8 * (t->scale_index - 1)), 8);

    long disp = (long)t->displacement;
    long base = (long)A;
    long idx = (long)B;
    long sc = (long)t->scale;

    return (uintptr_t)(disp + base + idx * sc);
}

/*
 * Riscrive il registro base in modo che l’istruzione originale, quando riprende, acceda a ea_prime.
 *
 * Solo indirizzamenti del tipo:
 *   [base + displacement]
 * quindi:
 * - no RIP-relative (non posso modificare RIP)
 * - base_index deve esserci
 * - scale_index deve essere 0
 */
static inline int mvmm_rewrite_base_reg_for_ea(instruction_record *ins,
                                               unsigned long regs,
                                               uintptr_t ea,       // indirizzo originale
                                               uintptr_t ea_prime) // indirizzo dello slot corrente
{
    if (ins->rip_relative == 'y')
        return 0;

    target_address *t = &ins->target;
    if (t->base_index == 0)
        return 0;

    if (t->scale_index != 0)
        return 0;

    // il delta é di quanto spostare il registro base
    intptr_t delta = (intptr_t)(ea_prime - ea);
    if (delta == 0)
        return 1;

    uint64_t base_val = 0;
    void *base_slot = (void *)(regs + 8 * (t->base_index - 1)); // prendo il registro base di regs perché acceda a ea_prime
    memcpy(&base_val, base_slot, 8);

    base_val = (uint64_t)((intptr_t)base_val + delta);
    memcpy(base_slot, &base_val, 8); // faccio il side effect sul registro base
    return 1;
}

/*
 * Registra una nuova regione mmap nella lista globale.
 */
static void mvmm_region_register(void *base, size_t len)
{
    if (base == MAP_FAILED || base == NULL || len == 0)
        return;

    // Alloca il nodo
    mvmm_region_node *node = (mvmm_region_node *)calloc(1, sizeof(*node));
    if (!node)
    {
        fprintf(stderr, "[mvmm] alloc region node failed\n");
        abort();
    }

    mvmm_region *r = &node->r;
    r->base = (uintptr_t)base;
    r->len = len;
    r->npages = (len + MVMM_PAGE_SIZE - 1) / MVMM_PAGE_SIZE; // arrotonda per eccesso

    r->pages = (mvmm_page_state *)calloc(r->npages, sizeof(*r->pages));
    if (!r->pages)
    {
        fprintf(stderr, "[mvmm] alloc pages failed\n");
        free(node);
        abort();
    }

    /*
     * Inizializza ogni pagina
     * slot 0 punta alla pagina reale
     */
    for (size_t i = 0; i < r->npages; i++)
    {
        mvmm_page_state *ps = &r->pages[i];

        atomic_store(&ps->last_ts_seen, UINT64_MAX); // timestamp impossibile
        atomic_store(&ps->cur_slot, 0);              // slot corrente 0

        atomic_store_explicit(&ps->slots[0], (void *)(r->base + i * MVMM_PAGE_SIZE), memory_order_relaxed); // indirizzo pagina 0
        atomic_store_explicit(&ps->slot_ts[0], 0, memory_order_relaxed);                                    // timestamp slot 0 a 0

        // tutte le altre pagine non le inizializziamo
        for (uint32_t s = 1; s < MVMM_MAX_VERSIONS; s++)
        {
            atomic_store_explicit(&ps->slots[s], NULL, memory_order_relaxed);
            atomic_store(&ps->slot_ts[s], UINT64_MAX);
        }
    }

    // aggiungi nuova regione in testa alla lista
    pthread_rwlock_wrlock(&g_regions_lock);
    node->next = g_regions_head;
    g_regions_head = node;
    pthread_rwlock_unlock(&g_regions_lock);

    MVMM_LOG("[mvmm] region registered base=%p len=%zu pages=%zu page_size=%d\n",
            base, len, r->npages, MVMM_PAGE_SIZE);
}

void *__real_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);

void *__wrap_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    void *p = __real_mmap(addr, length, prot, flags, fd, offset);
    if (p != MAP_FAILED)
    {
        mvmm_region_register(p, length);
    }
    return p;
}

/*
 * Traduce l'indirizzo effettivo ea verso la versione corrente della pagina.
 *
 * Se is_store=1:
 * - calcola un timestamp (wc/ROTATE_EVERY)
 * - alla prima store della pagina per quel ts fai copy on write e cur_slot = nuovo slot
 *
 * Se is_store=0:
 * - non crea versioni, ma traduce verso cur_slot corrente.
 */
static inline uintptr_t mvmm_translate_ea(mvmm_region *r,
                                          uintptr_t ea,
                                          int is_store)
{
    if (!r)
        return ea;

    uintptr_t page_base = ea & ~((uintptr_t)MVMM_PAGE_SIZE - 1);        // indirizzo base della pagina dell'ea originale
    size_t page_idx = (size_t)((page_base - r->base) / MVMM_PAGE_SIZE); // numero pagina
    if (page_idx >= r->npages)
        return ea;

    mvmm_page_state *ps = &r->pages[page_idx];

    // se é una scrittura aumenta il contatore e fai copy on write se comincia una nuova era
    if (is_store)
    {
        // aumenta timestamp
        uint64_t wc = atomic_fetch_add_explicit(&g_write_counter, 1, memory_order_relaxed) + 1; // contatore globale scritture

        /* trigger rollback globale quando raggiungiamo 500 store */
        mvmm_maybe_trigger_rollback(wc);

        uint64_t ts = wc / (uint64_t)ROTATE_EVERY; // era attuale

        // 1 sola copy on write per pagina per ts
        uint64_t seen = atomic_load_explicit(&ps->last_ts_seen, memory_order_acquire);
        if (seen != ts)
        { // nuova era
            if (atomic_compare_exchange_strong_explicit(&ps->last_ts_seen, &seen, ts,
                                                        memory_order_acq_rel, // vedo tutte le scritture precedenti e pubblico le nuove
                                                        memory_order_acquire  // vedi cose pubblicate dall'altro
                                                        ))
            { // lock free winner: solo il primo entra e aggiorna era
                uint32_t cur = atomic_load_explicit(&ps->cur_slot, memory_order_acquire);
                uint32_t next = (cur + 1u);
                if (next >= MVMM_MAX_VERSIONS)
                    next = 1; // non usare 0 (mantengo la baseline cosí)

                void *dst = NULL;

#if SINGLE_THREAD
                // In single-thread: riusa lo slot next se già allocato (evita OOM).
                dst = atomic_load_explicit(&ps->slots[next], memory_order_acquire);
                if (!dst)
                { // se non é allocata allocala
                    dst = mvmm_alloc_page();
                    if (!dst)
                        return ea;
                    atomic_store_explicit(&ps->slots[next], dst, memory_order_release);
                }
#else
                // In multi-thread alloc sempre nuova pagina
                dst = mvmm_alloc_page();
                if (!dst)
                    return ea;
#endif

                void *src = atomic_load_explicit(&ps->slots[cur], memory_order_acquire);
                if (!src)
                    return ea;

                memcpy(dst, src, MVMM_PAGE_SIZE);

                atomic_store_explicit(&ps->slot_ts[next], ts, memory_order_release);
                atomic_store_explicit(&ps->cur_slot, next, memory_order_release);

#if MVMM_DEBUG
                MVMM_LOG("[mvmm] COW ts=%lu region=%p page=%zu slot=%u\n",
                         (unsigned long)ts, (void *)r->base, page_idx, next);
#endif
            }
        }
    }

    // Traduci ea verso cur_slot mantenendo l’offset dentro pagina
    uintptr_t off = ea - page_base;
    void *curp = mvmm_cur_page_ptr(r, page_idx);
    if (!curp)
        return ea;
    return (uintptr_t)curp + off;
}

/**
 * Controlla se l'accesso attraversa il confine di pagina, dato un indirizzo effettivo e una dimensione.
 */
static inline int mvmm_is_cross_page(uintptr_t ea, size_t size)
{
    size_t off = (size_t)(ea & (MVMM_PAGE_SIZE - 1));
    return (off + size) > MVMM_PAGE_SIZE;
}

/*
 * entry point
 */
void the_patch(unsigned long mem, unsigned long regs)
{
    instruction_record *ins = (instruction_record *)mem;
    if (!ins)
        return;

    // solo load e store
    if (ins->type != 's' && ins->type != 'l')
        return;

    // calcola effective address
    uintptr_t ea = mvm_get_ea_u(ins, regs);
    if (ea == 0)
        return;

    // trova regione tra quelle tracciate
    mvmm_region *r = mvmm_find_region(ea);
    if (!r)
        return;

    size_t sz = (size_t)ins->data_size;
    if (sz != 0 && mvmm_is_cross_page(ea, sz))
    {
        MVMM_LOG("[mvmm] UNSUPPORTED cross-page %c ea=%p size=%zu\n",
                 ins->type, (void *)ea, sz);
        return;
    }

    // calcola ea' (versione corrente)
    int is_store = (ins->type == 's');
    uintptr_t ea_prime = mvmm_translate_ea(r, ea, is_store);

    // scrivi ea' nel registro di base di regs
    if (!mvmm_rewrite_base_reg_for_ea(ins, regs, ea, ea_prime))
        return;
}

// non usato
#define buffer user_defined_buffer
char buffer[1024];

void user_defined(instruction_record *actual_instruction, patch *actual_patch)
{
    (void)actual_instruction;
    (void)actual_patch;
}

// rollback

/* Rollback della regione r al timestamp target_ts.
 * Dopo questa chiamata, le load leggono dalla versione scelta.
 * La prima store aprirà una nuova versione sopra quella.
 *
 * non libera nulla, non gestisce munmap
 */
static void mvmm_region_rollback(mvmm_region *r, uint64_t target_ts)
{
    if (!r)
        return;

    // itero su tutte le pagine della regione
    for (size_t page_idx = 0; page_idx < r->npages; page_idx++)
    {
        mvmm_page_state *ps = &r->pages[page_idx];

        uint32_t best = 0;
        uint64_t best_ts = atomic_load_explicit(&ps->slot_ts[0], memory_order_acquire);

        // Cerca la miglior versione <= target_ts
        for (uint32_t s = 1; s < MVMM_MAX_VERSIONS; s++)
        {
            uint64_t ts = atomic_load_explicit(&ps->slot_ts[s], memory_order_acquire);
            if (ts == UINT64_MAX)
                continue; // slot vuoto
            if (ts > target_ts)
                continue; // troppo nuovo
            if (ts >= best_ts)
            { // più recente tra quelli ok
                best = s;
                best_ts = ts;
            }
        }

        // Pubblica la scelta
        atomic_store_explicit(&ps->cur_slot, best, memory_order_release);

        // forza il prossimo store a fare copy on write
        atomic_store_explicit(&ps->last_ts_seen, UINT64_MAX, memory_order_release);

        // Invalida tutte le versioni future
        for (uint32_t s = 1; s < MVMM_MAX_VERSIONS; s++)
        {
            uint64_t ts = atomic_load_explicit(&ps->slot_ts[s], memory_order_acquire);
            if (ts != UINT64_MAX && ts > target_ts)
            {
                atomic_store_explicit(&ps->slot_ts[s], UINT64_MAX, memory_order_release);
#if !SINGLE_THREAD
                atomic_store_explicit(&ps->slots[s], NULL, memory_order_release);
#endif
            }
        }

    MVMM_LOG("[mvmm] rollback page=%zu choose slot=%u best_ts=%lu\n",
            page_idx, best, (unsigned long)best_ts);
    }
}

static void mvmm_dump_state_locked(void)
{
    fprintf(stderr, "[mvmm] ===== DUMP STATE BEGIN =====\n");

    size_t rix = 0;
    for (mvmm_region_node *n = g_regions_head; n; n = n->next, rix++)
    {
        mvmm_region *r = &n->r;
        fprintf(stderr, "[mvmm] region[%zu] base=%p len=%zu npages=%zu\n",
                rix, (void *)r->base, r->len, r->npages);

        /* Per non stampare troppo, se vuoi limita il numero di pagine */
        for (size_t page_idx = 0; page_idx < r->npages; page_idx++)
        {
            mvmm_page_state *ps = &r->pages[page_idx];

            uint32_t cur = atomic_load_explicit(&ps->cur_slot, memory_order_acquire);
            uint64_t last = atomic_load_explicit(&ps->last_ts_seen, memory_order_acquire);

            fprintf(stderr, "  page[%zu]: cur_slot=%u last_ts_seen=%s\n",
                    page_idx, cur,
                    (last == UINT64_MAX) ? "UINT64_MAX" : "set");

            for (uint32_t s = 0; s < MVMM_MAX_VERSIONS; s++)
            {
                uint64_t ts = atomic_load_explicit(&ps->slot_ts[s], memory_order_acquire);
                void *p = atomic_load_explicit(&ps->slots[s], memory_order_acquire);

                if (ts == UINT64_MAX && p == NULL)
                {
                    fprintf(stderr, "    slot[%u]: EMPTY\n", s);
                }
                else
                {
                    fprintf(stderr, "    slot[%u]: ts=%s%lu ptr=%p%s\n",
                            s,
                            (ts == UINT64_MAX) ? "UINT64_MAX(" : "",
                            (unsigned long)ts,
                            p,
                            (ts == UINT64_MAX) ? ")" : "");
                }
            }
        }
    }

    fprintf(stderr, "[mvmm] ===== DUMP STATE END =====\n");
}

static void mvmm_rollback_all(uint64_t target_ts)
{
    pthread_rwlock_rdlock(&g_regions_lock);

    /* dump prima del rollback */
#if MVMM_DEBUG
    fprintf(stderr, "[mvmm] rollback_all target_ts=%lu (BEFORE)\n",
            (unsigned long)target_ts);
    mvmm_dump_state_locked();
#endif

    for (mvmm_region_node *n = g_regions_head; n; n = n->next)
    {
        mvmm_region_rollback(&n->r, target_ts);
    }

    /* dump dopo il rollback */
#if MVMM_DEBUG
    fprintf(stderr, "[mvmm] rollback_all target_ts=%lu (AFTER)\n",
            (unsigned long)target_ts);
    mvmm_dump_state_locked();
#endif

    pthread_rwlock_unlock(&g_regions_lock);
}

static inline void mvmm_maybe_trigger_rollback(uint64_t wc_now)
{
    if (MVMM_ROLLBACK_AT_WRITES == 0)
        return;

    // trigger solo su multipli esatti
    if ((wc_now % (uint64_t)MVMM_ROLLBACK_AT_WRITES) != 0)
        return;

    // assicurati che per quel wc ci entri una sola volta (lock-free)
    uint64_t last = atomic_load_explicit(&g_last_rollback_wc, memory_order_acquire);
    if (last == wc_now)
        return;

    if (!atomic_compare_exchange_strong_explicit(&g_last_rollback_wc, &last, wc_now,
                                                 memory_order_acq_rel, memory_order_acquire))
        return;

    // era corrente (coerente con la tua definizione)
    uint64_t ts_now = wc_now / (uint64_t)ROTATE_EVERY;

    // torna due versioni indietro
    uint64_t target_ts = (ts_now >= 2) ? (ts_now - 2) : 0;

    mvmm_rollback_all(target_ts);

#if MVMM_DEBUG
    fprintf(stderr, "[mvmm] rollback TRIGGERED wc=%lu ts_now=%lu target_ts=%lu\n",
            (unsigned long)wc_now, (unsigned long)ts_now, (unsigned long)target_ts);
#endif
}
