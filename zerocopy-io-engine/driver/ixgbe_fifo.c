#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ixgbe_fifo.h"

static inline uint32_t myrand(uint32_t *next, uint32_t cpu_id)
{
	*next = *next * (1103515245 ) + 12345 + cpu_id * 16;
	return((uint64_t)(*next/65535) % 32768);
}

inline uint64_t read_tsc()
{
	uint64_t        time;
	uint32_t        msw   , lsw;
	__asm__         __volatile__("rdtsc\n\t"
			"movl %%edx, %0\n\t"
			"movl %%eax, %1\n\t"
			:         "=r"         (msw), "=r"(lsw)
			:
			:         "%edx"      , "%eax");
	time = ((uint64_t) msw << 32) | lsw;
	return time;
}

inline void wait_ticks(uint64_t ticks)
{
    uint64_t        current_time;
    uint64_t        time = read_tsc();
    time += ticks;
    do {
        current_time = read_tsc();
    } while (current_time < time);
}

/* Insert: called by the producer */
inline int insert(FIFO_CTRL * fifo, FIFO_BUFFER * buffer, ELEMENT_TYPE element)
{
	uint32_t afterNextWrite = ELEM_NEXT(FIFO_NEXT_WRITE(fifo));
	if( afterNextWrite == FIFO_LOCAL_READ(fifo) ) {
		if( afterNextWrite == FIFO_READ(fifo) ) {
			return INSERT_FAILED;
		}
		FIFO_LOCAL_READ(fifo) = FIFO_READ(fifo);
	}
	BUFFER_ELEM(buffer, FIFO_NEXT_WRITE(fifo)) = element;
	FIFO_NEXT_WRITE(fifo) = afterNextWrite;
	FIFO_W_BATCH(fifo) ++;
	if( FIFO_W_BATCH(fifo) >= FIFO_BATCH_SIZE(fifo) ) {
		FIFO_WRITE(fifo) = FIFO_NEXT_WRITE(fifo);
		FIFO_W_BATCH(fifo) = 0;
	}
	return SUCCESS;
}

/* Extract: called by the consumer */
inline int extract(FIFO_CTRL * fifo, FIFO_BUFFER * buffer, ELEMENT_TYPE * element)
{
	if( FIFO_NEXT_READ(fifo) == FIFO_LOCAL_WRITE(fifo) ) {
		if( FIFO_NEXT_READ(fifo) == FIFO_WRITE(fifo)) {
			return EXTRACT_FAILED;
		}
		FIFO_LOCAL_WRITE(fifo) = FIFO_WRITE(fifo);
	}
	*element = BUFFER_ELEM(buffer, FIFO_NEXT_READ(fifo));
	FIFO_NEXT_READ(fifo) = ELEM_NEXT(FIFO_NEXT_READ(fifo));
	FIFO_R_BATCH(fifo) ++;
	if( FIFO_R_BATCH(fifo) >= FIFO_BATCH_SIZE(fifo) ) {
		FIFO_READ(fifo) = FIFO_NEXT_READ(fifo);
		FIFO_R_BATCH(fifo) = 0;
	}
	return SUCCESS;
}
