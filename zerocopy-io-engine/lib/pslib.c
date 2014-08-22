#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <sys/mman.h>
#include <sys/ioctl.h>

#include "../include/ps.h"

int ps_list_devices(struct ps_device *devices)
{
	struct ps_handle handle;
	int ret;

	if (ps_init_handle(&handle))
		return -1;

	ret = ioctl(handle.fd, PS_IOC_LIST_DEVICES, devices);
	
	ps_close_handle(&handle);

	return ret;
}

int ps_init_handle(struct ps_handle *handle)
{
	memset(handle, 0, sizeof(struct ps_handle));

	handle->fd = open("/dev/packet_shader_ixgbe", O_RDWR);
	if (handle->fd == -1)
		return -1;

	return 0;
}

void ps_close_handle(struct ps_handle *handle)
{
	close(handle->fd);
	handle->fd = -1;
}

int ps_attach_rx_device(struct ps_handle *handle, struct ps_queue *queue)
{
	return ioctl(handle->fd, PS_IOC_ATTACH_RX_DEVICE, queue);
}

int ps_detach_rx_device(struct ps_handle *handle, struct ps_queue *queue)
{
	return ioctl(handle->fd, PS_IOC_DETACH_RX_DEVICE, queue);
}

int ps_alloc_chunk(struct ps_handle *handle, struct ps_chunk *chunk)
{
#ifdef ZERO_COPY_IOENGINE
    off_t  offset;
    struct ps_queue queue;
#ifndef PAGE_SHIFT
#define PAGE_SHIFT (12)
#endif
    queue.qidx = chunk->queue.qidx;
    queue.ifindex = chunk->queue.ifindex;
    offset = queue.qidx << PAGE_SHIFT;
    offset |= queue.ifindex << (PAGE_SHIFT + QIDX_BITS);
#endif
	memset(chunk, 0, sizeof(*chunk));

	chunk->info = (struct ps_pkt_info *)malloc(
			sizeof(struct ps_pkt_info) * MAX_CHUNK_SIZE);
	if (!chunk->info)
		return -1;

#ifdef ZERO_COPY_IOENGINE
	chunk->buf = (char *)mmap(NULL, MAX_PACKET_SIZE * MAX_CHUNK_SIZE * 2, 
			PROT_READ | PROT_WRITE, MAP_SHARED,
			handle->fd, offset);
    chunk->queue.ifindex = queue.ifindex;
    chunk->queue.qidx = queue.qidx;
#else
	chunk->buf = (char *)mmap(NULL, MAX_PACKET_SIZE * MAX_CHUNK_SIZE, 
			PROT_READ | PROT_WRITE, MAP_SHARED,
			handle->fd, 0);
#endif
	if ((long)chunk->buf == -1)
		return -1;

	return 0;
}

void ps_free_chunk(struct ps_chunk *chunk)
{
	free(chunk->info);

#ifndef ZERO_COPY_IOENGINE
	munmap(chunk->buf, MAX_PACKET_SIZE * MAX_CHUNK_SIZE);
#else
	munmap(chunk->buf, MAX_PACKET_SIZE * MAX_CHUNK_SIZE * 2);
#endif    

	chunk->info = NULL;
	chunk->buf = NULL;
}

int ps_recv_chunk(struct ps_handle *handle, struct ps_chunk *chunk)
{
	int cnt;

	cnt = ioctl(handle->fd, PS_IOC_RECV_CHUNK, chunk);
	if (cnt > 0) {
		int i;
		int qidx = chunk->queue.qidx;

		handle->rx_chunks[qidx]++;
		handle->rx_packets[qidx] += cnt;

		for (i = 0; i < cnt; i++)
			handle->rx_bytes[qidx] += chunk->info[i].len;
	}

	return cnt;
}

/* Send the given chunk to the modified driver. */
int ps_send_chunk(struct ps_handle *handle, struct ps_chunk *chunk)
{
	int cnt;
    int tmp;
    int front;

	cnt = ioctl(handle->fd, PS_IOC_SEND_CHUNK, chunk);
	if (cnt >= 0) {
		//int i;
		int ifindex = chunk->queue.ifindex;

		handle->tx_chunks[ifindex]++;
		handle->tx_packets[ifindex] += cnt;

        chunk->cnt -= cnt;
        front = chunk->front;

        chunk->front = (chunk->front + cnt) & (MAX_CHUNK_SIZE - 1);

        tmp = cnt;
        while(tmp-- > 0) {
            handle->tx_bytes[ifindex] += chunk->info[front].len;
            front = (front + 1) & (MAX_CHUNK_SIZE - 1);
        }

		/*for (i = 0; i < cnt; i++)
			handle->tx_bytes[ifindex] += chunk->info[i].len;
        */
	}

	return cnt;
}

int ps_slowpath_packet(struct ps_handle *handle, struct ps_packet *packet)
{
	return ioctl(handle->fd, PS_IOC_SLOWPATH_PACKET, packet);
}

static int num_cpus = 0;
int get_num_cpus()
{
	if(0 == num_cpus)
		num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	return num_cpus;
}

int bind_cpu(int cpu)
{
    cpu_set_t *cmask;
	size_t n;
	int ret;

	n = get_num_cpus();

    if (cpu < 0 || cpu >= (int)n) {
		errno = -EINVAL;
		return -1;
	}

	cmask = CPU_ALLOC(n);
	if (cmask == NULL)
		return -1;

    CPU_ZERO_S(n, cmask);
    CPU_SET_S(cpu, n, cmask);

    ret = sched_setaffinity(0, n, cmask);

	CPU_FREE(cmask);

	return ret;
}

int get_microsecond(uint64_t *ptr_use_microsec, const struct timeval *start, const struct timeval *end)
{
	int64_t use_sec, use_microsec;

	if(start->tv_sec > end->tv_sec){
		printf("ERROR: start time is later than end time\n");
		return ERR_FLAG;
	}
	if(start->tv_sec == end->tv_sec && start->tv_usec > end->tv_usec){
		printf("ERROR: start time is later than end time\n");
		return ERR_FLAG;
	}

	use_sec = end->tv_sec - start->tv_sec;
	use_microsec = end->tv_usec - start->tv_usec;

	if(use_microsec < 0){
		use_sec--;
		use_microsec += 1000000;
	}
	*ptr_use_microsec = (uint64_t)use_microsec + use_sec*1000000;

	return SUCCESS_FLAG;
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

void wait_ticks(uint64_t ticks)
{
    uint64_t        current_time;
    uint64_t        time = read_tsc();
    time += ticks;
    do {
        current_time = read_tsc();
    } while (current_time < time);
}
