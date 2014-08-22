#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/time.h>

#include "../../include/ps.h"

int num_cpus;
int my_cpu;

struct timeval start, end;

void stat_signal(int origin_signal);

void dump_packet(char *buf, int len)
{
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct udphdr *udph;
	struct tcphdr *tcph;
	uint8_t *t;

	ethh = (struct ethhdr *)buf;
	printf("%02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X ",
			ethh->h_source[0],
			ethh->h_source[1],
			ethh->h_source[2],
			ethh->h_source[3],
			ethh->h_source[4],
			ethh->h_source[5],
			ethh->h_dest[0],
			ethh->h_dest[1],
			ethh->h_dest[2],
			ethh->h_dest[3],
			ethh->h_dest[4],
			ethh->h_dest[5]);

	if (ntohs(ethh->h_proto) != ETH_P_IP) {
		printf("protocol %04hx  ", ntohs(ethh->h_proto));
		goto done;
	}

	printf(" ");

	iph = (struct iphdr *)(ethh + 1);
	udph = (struct udphdr *)((uint32_t *)iph + iph->ihl);
	tcph = (struct tcphdr *)((uint32_t *)iph + iph->ihl);

	t = (uint8_t *)&iph->saddr;
	printf("%u.%u.%u.%u", t[0], t[1], t[2], t[3]);
	if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
		printf("(%d)", ntohs(udph->source));

	printf(" -> ");

	t = (uint8_t *)&iph->daddr;
	printf("%u.%u.%u.%u", t[0], t[1], t[2], t[3]);
	if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
		printf("(%d)", ntohs(udph->dest));

	printf(" TTL=%d ", iph->ttl);

	if (ip_fast_csum(iph, iph->ihl)) {
		__sum16 org_csum, correct_csum;
		
		org_csum = iph->check;
		iph->check = 0;
		correct_csum = ip_fast_csum(iph, iph->ihl);
		printf("(bad checksum %04x should be %04x) ",
				ntohs(org_csum), ntohs(correct_csum));
		iph->check = org_csum;
	}

	switch (iph->protocol) {
	case IPPROTO_TCP:
		printf("TCP ");
		if (tcph->syn)
			printf("S ");
		if (tcph->fin)
			printf("F ");
		if (tcph->ack)
			printf("A ");
		if (tcph->rst)
			printf("R ");

		printf("seq %u ", ntohl(tcph->seq));
		if (tcph->ack)
			printf("ack %u ", ntohl(tcph->ack_seq));
		break;
	case IPPROTO_UDP:
		printf("UDP ");
		break;
	default:
		printf("protocol %d ", iph->protocol);
		goto done;
	}

done:
	printf("len=%d\n", len);
}

int num_devices;
struct ps_device devices[MAX_DEVICES];

//struct ps_handle handle;
struct ps_handle handles[MAX_DEVICES];
int num_devices_attached;
int devices_attached[MAX_DEVICES];

void print_usage(char *argv0)
{
	fprintf(stderr, "Usage: %s <interface to sniff> <...>",
			argv0);

	exit(2);
}

void parse_opt(int argc, char **argv)
{
	int i, j;

	if (argc < 2)
		print_usage(argv[0]);

	for (i = 1; i < argc; i++) {
		int ifindex = -1;

		for (j = 0; j < num_devices; j++) {
			if (strcmp(argv[i], devices[j].name) != 0)
				continue;

			ifindex = devices[j].ifindex;
			break;
		}

		if (ifindex == -1) {
			fprintf(stderr, "Interface %s does not exist!\n", argv[i]);
			exit(4);
		}

		for (j = 0; j < num_devices_attached; j++) {
			if (devices_attached[j] == ifindex)
				goto already_attached;
		}

		devices_attached[num_devices_attached] = ifindex;
		num_devices_attached++;

already_attached:
		;
	}

	assert(num_devices_attached > 0);
}

void attach()
{
	int ret;
	//int i, j;
	int i; 

	//ret = ps_init_handle(&handle);
	ret = ps_init_handle(&handles[my_cpu]);
	if (ret != 0) {
		perror("ps_init_handle");
		exit(1);
	}

	for (i = 0; i < num_devices_attached; i++) {
		struct ps_queue queue;

		queue.ifindex = devices_attached[i];

		//for (j = 0; j < devices[devices_attached[i]].num_rx_queues; j++) {
			//queue.qidx = j;
			queue.qidx = my_cpu;

			ret = ps_attach_rx_device(&handles[my_cpu], &queue);
			if (ret != 0) {
				perror("ps_attach_rx_device");
				exit(1);
			}
		//}
	}
}

void dump()
{
	int ret;
	struct ps_chunk chunk;
    char flag = 0;
    struct ps_handle* handle = &handles[my_cpu];

	chunk.queue.ifindex = devices_attached[0];
	chunk.queue.qidx = my_cpu;
	ret = ps_alloc_chunk(handle, &chunk);
	if (ret != 0) {
		perror("ps_alloc_chunk");
		exit(1);
	}

	chunk.cnt = 128; /* no batching */
	chunk.recv_blocking = 1;


	for (;;) {
		int ret = ps_recv_chunk(handle, &chunk);

		if (ret < 0) {
			if (errno == EINTR){
                printf("dump errno == EINTR\n");
				continue;
            }

			if (!chunk.recv_blocking && errno == EWOULDBLOCK){
                printf("dump !chunk.recv_blocking && errno == EWOULDBLOCK\n");
				break;
            }

			assert(0);
		}
        if(ret > 0) {
            if(!flag) {
                flag = 1;
                gettimeofday(&start, NULL);
            }
            else 
                stat_signal(0);
            chunk.retcnt = ret;
            chunk.front = (chunk.front + ret) & (MAX_CHUNK_SIZE - 1);
        }

	}
}

extern int get_microsecond(uint64_t*, const struct timeval*, const struct timeval*);

void stat_signal(int origin_signal)
{
    struct ps_queue queue;
    uint64_t during;
    struct ps_handle handle = handles[my_cpu];
    static time_t last_sec = 0;
    static char first = 1;
    /*static long last_rx_bytes = 0;
    static long last_rx_pkts = 0;
    long diff_time = 0;
    double pps = 0.0, bps = 0.0;
    */

    gettimeofday(&end, NULL);
    if(end.tv_sec <= last_sec)
        return;
    //diff_time = end.tv_sec - last_sec;

    get_microsecond(&during, &start, &end);
    if(SIGINT == origin_signal || !first) {
        printf("xge%d:queue %d: bps: %3.5lf Gbps, pps: %3.5lf Mpps, rx chunks: %ld rx pkts: %ld, rx bytes: %ld, mean pkt per chunk: %lf\n",
		    	devices_attached[0], my_cpu,
                (handle.rx_bytes[my_cpu] + handle.rx_packets[my_cpu] * 24.0) * 8.0 / during / 1000,
                handle.rx_packets[my_cpu] * 1.0 / during,
                handle.rx_chunks[my_cpu],
                handle.rx_packets[my_cpu],
                handle.rx_bytes[my_cpu],
                handle.rx_packets[my_cpu] * 1.0 / handle.rx_chunks[my_cpu]);

        /*bps = handle.rx_bytes[my_cpu] - last_rx_bytes;
        last_rx_bytes = handle.rx_bytes[my_cpu];
        pps = handle.rx_packets[my_cpu] - last_rx_pkts;
        last_rx_pkts = handle.rx_packets[my_cpu];

        bps += pps * 24;
        bps = bps * 8;
        bps /= diff_time*1000000000;
        pps /= diff_time*1000000;
        printf("xge%d: queue %d: bps: %3.5lf Gbps, pps: %3.5lf Mpps\n",
                devices_attached[0], my_cpu, bps, pps);
        */
        if(SIGINT == origin_signal) {
            queue.ifindex = devices_attached[0];
            queue.qidx = my_cpu;
            ps_detach_rx_device(&handle, &queue);
            ps_close_handle(&handle);
            signal(SIGINT, SIG_DFL);
            kill(getpid(), SIGINT);
        }
    }
    
    //if(end.tv_sec > last_sec) {
        first = 0;
        last_sec = end.tv_sec;
    //}
}

int main(int argc, char **argv)
{
	num_devices = ps_list_devices(devices);
	if (num_devices == -1) {
		perror("ps_list_devices");
		exit(1);
	}

	parse_opt(argc, argv);

	num_cpus = get_num_cpus();
	assert(num_cpus >= 1);

	for (my_cpu = 0; my_cpu < num_cpus; my_cpu++) {
		int ret = fork();
		assert(ret >= 0);

		if (ret == 0) {
			bind_cpu(my_cpu);
			signal(SIGINT, stat_signal);
			
	        attach();
			dump();

			return 0;
		}
	}
	signal(SIGINT, SIG_IGN);
    while(1) {
        int ret = wait(NULL);
        if(-1 == ret && ECHILD == errno)
            break;
    }

	return 0;
}
