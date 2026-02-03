#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>

#define NUM_THREADS 1

#define MEM_SIZE (2<<21)

void* function(void * whoami){
    long me = (long)whoami;
    int *p;

    printf("thread %ld active\n", me);

    p = (int*)mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }

    size_t page = (size_t)getpagesize();
    size_t ints_per_page = page / sizeof(int);

    int pages_to_touch = 64; // tocca 64 pagine diverse
    for (int i = 0; i < pages_to_touch; i++) {
        p[i * (int)ints_per_page] = (int)(me * 1000 + i);
    }

    // molte scritture per far avanzare il contatore (timestamp)
    for (int round = 0; round < 20000; round++) {
        int idx = (round % pages_to_touch) * (int)ints_per_page;
        p[idx] = p[idx] + 1;
    }

    printf("thread %ld done, sample=%d\n", me, p[0]);
    fflush(stdout);
    return NULL;
}


int main(int argc, char * argv){

	pthread_t tid[NUM_THREADS];
	long i=0;

	goto job;

job:
	pthread_create(&tid[i],NULL,function,(void*)i);
	if(++i < NUM_THREADS) goto job;

	for(i=0;i<NUM_THREADS;i++){
		pthread_join(tid[i],NULL);
	}

        return 0;
}


