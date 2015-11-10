#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include "zcopy.h"

#define MSIZE (500)

/* add checksum for ip hdr, code from arch/x86/include/asm/checksum_64.h */
static inline unsigned short ip_fast_csum(const unsigned char *iph, unsigned int ihl)
{
	unsigned int sum;

	asm("  movl (%1), %0\n"
			"  subl $4, %2\n"
			"  jbe 2f\n"
			"  addl 4(%1), %0\n"
			"  adcl 8(%1), %0\n"
			"  adcl 12(%1), %0\n"
			"1: adcl 16(%1), %0\n"
			"  lea 4(%1), %1\n"
			"  decl %2\n"
			"  jne      1b\n"
			"  adcl $0, %0\n"
			"  movl %0, %2\n"
			"  shrl $16, %0\n"
			"  addw %w2, %w0\n"
			"  adcl $0, %0\n"
			"  notl %0\n"
			"2:"
			/* Since the input registers which are loaded with iph and ihl
			   are modified, we must also specify them as outputs, or gcc
			   will assume they contain their original values. */
			: "=r" (sum), "=r" (iph), "=r" (ihl)
			: "1" (iph), "2" (ihl)
			   : "memory");
	return (sum);
}

int depacket(void *addr, struct in_addr *src, struct in_addr *dst, int * proto, int *offset, int *len, int *checksum)
{
	int ihl = 0;
	int version = 0;
	uint16_t frag_off;

	if (addr == NULL || src == NULL || dst == NULL || proto == NULL || offset == NULL || len == NULL || checksum == NULL)  {
		fprintf(stderr, "depacket() error, some paramenters may be NULL\n");
		return -1;
	}

	ihl = ((struct iphdr *)addr)->ihl;
	version = ((struct iphdr *)addr)->version;
	if (ihl < 5 || version != 4) {
		fprintf(stderr, "depacket() error, Got a invalid packet, with header length: %d version: %d\n", ihl, version);
		return -1;
	}

	src->s_addr = ((struct iphdr *)addr)->saddr;
	dst->s_addr = ((struct iphdr *)addr)->daddr;
	*len = (int)ntohs(((struct iphdr *)addr)->tot_len);
	*proto = (int)((struct iphdr *)addr)->protocol;
	*checksum = (int) ip_fast_csum((const unsigned char *)addr, ihl);

	/* the top 3 bits are used for Flags, removing it! */
	frag_off = ((struct iphdr *)addr)->frag_off;
	*offset = (int)((frag_off & 0x1fff) * 8);

	return 0;
}
static inline int is_not_ip(void * ptr)
{
	struct ethhdr * eth = (struct ethhdr *)ptr;
	return eth->h_proto != htons(ETH_P_IP);
}

int main(int argc, char ** argv)
{
	int ret = 0;
	unsigned int r = 0;
	int proto;
	int ip_len, len;
	int offset;
	int csum;
	int times = 100, forevery = 0;
	int stream_num = 1;
	unsigned int count = 0;
	struct in_addr srcaddr;
	struct in_addr dstaddr;
	struct queue_status status;
	struct request_devices dev;
	memset(&dev, '\0', sizeof(struct request_devices));
	dev.recv_count = 1;
	dev.recv_buffer_size = MSIZE;

	if(argc != 4)
	{
		printf("Usage: %s <netcard> <cycle> <queue_num>\n", argv[0]);
		exit(-1);
	}

	strcpy(dev.recv_nics[0].dev_name, argv[1]);
	times = atoi(argv[2]);
	dev.queue_num = atoi(argv[3]);

	ret = init_queues(&dev);
	if(ret)
	{
		printf("init queue error\n");
		pause();
		exit(-1);
	}
	if(times == 0)
		forevery = 1;

	status.queue_num = dev.queue_num;

	while(times || forevery)
	{
		int index;
		void * p;
		char source[16],dest[16];
		void * addr = get_receive_packet(r, &index);
		++r;
		if(r >= dev.queue_num)
			r = 0;

		if(addr == NULL)
		{
		//	usleep(1);
			continue;
		}
		
		if(is_not_ip(addr))
		{
			goto drop_pack;
		}
		
		p = addr;
		addr += sizeof(struct ethhdr);
		proto = 0;
		len = 0;
		offset = 0;
		csum = 0;
		memset(source, 0, sizeof(source));
		memset(dest, 0, sizeof(dest));
		if(depacket(addr, &srcaddr, &dstaddr, &proto, &offset, &ip_len, &csum))
			goto drop_pack;
		
		--times;
		++count;
		
		if (csum != 0)
		{
			printf("ID: %4d, packet check sum error! (queue %d)\n", count, r);
		}
		else if(!(count % 100))
		{
			len = get_packet_length(index);
			//inet_ntop also is ok
			memcpy(source, inet_ntoa(srcaddr), strlen(inet_ntoa(srcaddr))); 
			memcpy(dest, inet_ntoa(dstaddr), strlen(inet_ntoa(dstaddr))); 
			printf("count %4d len %d index %d packet from %16s to %16s, proto: %d, offset/length: %4d/%4d (queue %d)\n",
					count, len, index, source, dest, proto, offset, ip_len, r);
/*			{
				int q = 0;
				get_queue_status("eth0", &status);
				for(q = 0; q < status.queue_num; ++q)
					printf("queue %d: total packets %u, free packets %u.\n", q, status.total_per_queue[q], status.free_per_queue[q]);
			}
*/
		}
drop_pack:
		if(drop_receive_packet(index))
			printf("drop packet index %d error\n", index);
	}
	release_queues();
	exit(0);
}
