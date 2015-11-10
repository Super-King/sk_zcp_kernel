#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <netdb.h>

#include "zcopy.h"

#define MSIZE (512)
struct psd_header 
{
	unsigned int s_ip;//source ip
	unsigned int d_ip;//dest ip
	unsigned char mbz;//0
	unsigned char proto;//proto type
	unsigned short len;//

};

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

static void handle_ip(unsigned int * ip, char * hostname)
{
	struct hostent *host_ent;
	if(inet_pton(AF_INET, hostname, ip) <= 0)
	{
		if ((host_ent = gethostbyname(hostname)) == NULL)
		{
			printf("ip addr error !\n");
			return;
		}
		memcpy((void*)ip, host_ent->h_addr, host_ent->h_length);
	}
}
int construct_packet(void * ptr, int r)
{
	int len;
	struct psd_header psb;
	struct ethhdr * eth;
	struct iphdr * ip;
	struct udphdr * udp;
	eth = (struct ethhdr *)ptr;
	ptr += sizeof(struct ethhdr);
	ip = (struct iphdr *)ptr;
	ptr += sizeof(struct iphdr);
	udp = (struct udphdr *)ptr;
	
	eth->h_proto = htons(ETH_P_IP);
	memset(eth->h_source, 0xAA, 6);
	memset(eth->h_dest, 0xBB, 6);

	ip->version = IPVERSION;
	ip->ihl = sizeof(struct iphdr) >> 2;
	ip->tos = 0;
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = IPPROTO_UDP;
	ip->tot_len = htons((ip->ihl << 2) + sizeof(struct udphdr) + 20);
	handle_ip(&ip->saddr, "192.168.0.1");
	handle_ip(&ip->daddr, "192.168.0.2");
	ip->check = 0;
	ip->check = ip_fast_csum((unsigned char *)ip, ip->ihl);

	udp->source = htons(r % 65535);
	udp->dest = htons(65535 - (r % 65535));
	udp->len = htons(sizeof(struct udphdr));
	udp->check = 0;

	psb.s_ip = ip->saddr;
	psb.d_ip = ip->daddr;
	psb.mbz = 0;
	psb.proto = IPPROTO_UDP;
	psb.len = udp->len;

	udp->check = ip_fast_csum((unsigned char *)&psb, sizeof(struct psd_header));
	len = ntohs(ip->tot_len) + sizeof(struct ethhdr);

	return len;
}
int main(int argc, char ** argv)
{
	int ret = 0;
	unsigned int r = 0;
	int times = 100, forevery = 0;
	int len;
	int stream_num = 1;
	unsigned int count = 0;
	struct in_addr srcaddr;
	struct in_addr dstaddr;
	struct request_devices dev;
	memset(&dev, '\0', sizeof(struct request_devices));
	dev.send_count = 1;
	dev.send_buffer_size = MSIZE;

	if(argc != 4)
	{
		printf("Usage: %s <netcard> <times> <queue_num>\n", argv[0]);
		exit(-1);
	}

	strcpy(dev.send_nics[0].dev_name, argv[1]);
	times = atoi(argv[2]);
	dev.queue_num = atoi(argv[3]);

	ret = init_queues(&dev);

	if(ret)
	{
		printf("init queue error\n");
		exit(-1);
	}

	if(times == 0)
		forevery = 1;
	printf("start send !\n");
	while(times-- || forevery)
	{
		int index;
		r =  rand() % dev.queue_num;
		void * addr = get_send_buffer(&index);
		len = construct_packet(addr, times);
		if(send_packet(dev.send_nics[0].nic_index, index, len))
		{
			printf("send packet index %d len %d failed!\n", index, len);
		}
		usleep(1000);
	}
	printf("send over !\n");
	sleep(10);
	release_queues();
	exit(0);
}
