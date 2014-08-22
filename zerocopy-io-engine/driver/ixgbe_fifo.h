#ifndef _IXGBE_FIFO_H_
#define _IXGBE_FIFO_H_

#include <linux/types.h>

/*typedef struct{
    union {
	    uint32_t index;
        struct {
            uint32_t bidx:15;
            uint32_t qidx:8;
            uint32_t ifidx:9;
        }dmi;
    };
} FIFO_ELEM __attribute__ ((aligned(4)));
*/
typedef struct{
	uint16_t index;
} FIFO_ELEM __attribute__ ((aligned(2)));
#define FIFO_ELEM_DATA(p)	((p)->index)

#define CACHE_LINE			64 //! Cache-line size for X86 
#define ELEMENT_TYPE		FIFO_ELEM
//#define ELEM_SIZE			(5456) //! 8192*2/3 = 5461, 5456 % 16 == 0
#define ELEM_SIZE			(4096) //! Should be/ 2^N
#define ELEM_SIZE_MASK		(ELEM_SIZE - 1)
//#define BATCH_SIZE		(50)
//#define BATCH_SIZE		    (16)	
#define BATCH_SIZE		(1)	

#define INSERT_FAILED		(-1)
#define EXTRACT_FAILED		(-2)
#define SUCCESS				(0)

/* Variable definitions */
typedef struct{
	/* shared control variables */
	volatile uint32_t read __attribute__ ((aligned(64)));
	volatile uint32_t write;

	/* consumer's local variables */
	uint32_t localWrite __attribute__ ((aligned(64)));
	uint32_t nextRead;
	uint32_t rBatch;
	uint32_t rbatchSize; //dynamic recycling

	/* producer's local variables */
	uint32_t localRead __attribute__ ((aligned(64)));
	uint32_t nextWrite;
	uint32_t wBatch;

	/* constants */
	uint32_t max __attribute__ ((aligned(64)));
	uint32_t batchSize;
} FIFO_CTRL __attribute__ ((aligned(128)));

#define FIFO_READ(p)		((p)->read)	
#define FIFO_WRITE(p)		((p)->write)

#define FIFO_LOCAL_WRITE(p)	((p)->localWrite)
#define FIFO_NEXT_READ(p)	((p)->nextRead)
#define FIFO_R_BATCH(p)		((p)->rBatch)

#define FIFO_LOCAL_READ(p)	((p)->localRead)
#define FIFO_NEXT_WRITE(p)	((p)->nextWrite)
#define FIFO_W_BATCH(p)		((p)->wBatch)

#define FIFO_MAX(p)		((p)->max)
#define FIFO_BATCH_SIZE(p)	((p)->batchSize)

/* buffer definitions */
typedef struct{
	ELEMENT_TYPE buffer[ELEM_SIZE];
} FIFO_BUFFER __attribute__((aligned(64)));

#define BUFFER_ELEM(p, i)	((p)->buffer[i])
#define BUFFER_ELEM_PTR(p, i)	(&((p)->buffer[i]))
#define ELEM_NEXT(i)		(((i)+1) & ELEM_SIZE_MASK)

int insert(FIFO_CTRL *, FIFO_BUFFER *, ELEMENT_TYPE);
int extract(FIFO_CTRL *, FIFO_BUFFER *, ELEMENT_TYPE *);
uint64_t read_tsc(void);
void wait_ticks(uint64_t ticks);

#endif //end of define _IXGBE_FIFO_H_
