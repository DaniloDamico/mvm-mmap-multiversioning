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

#define MEM_SIZE 4096


void* function(void * whoami){
	int i;
	int * p;
	long me = (long)whoami;
	char * aux;
	
	printf("thread %ld active\n",me);

	p = (int*)mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

	if(!p){
		printf("(%ld) mmap error - returning\n",me);
		fflush(stdout);
		return NULL;
	}

	for(i = 0; i < 20; i++){
		p[i] = i;
	}

	for(i = 0; i < 20; i++){
		printf("(%ld) p[%d] = %d\n", me, i, p[i]);
		fflush(stdout);
	}

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