#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "zcopy.h"

#define MSIZE (512)

int main(int argc, char ** argv)
{
	int ret = 0;
	unsigned int r = 0;
	int times = 100, forevery = 0;
	int stream_num = 1;
	unsigned int count = 0;
	struct request_devices dev;
	memset(&dev, '\0', sizeof(struct request_devices));
	dev.recv_count = 1;
	dev.send_count = 1;
	dev.recv_buffer_size = MSIZE;
	dev.send_buffer_size = MSIZE;

	if(argc != 4)
	{
		printf("Usage: %s <netcard> <cycle> <queue_num>\n", argv[0]);
		exit(-1);
	}
	strcpy(dev.recv_nics[0].dev_name, argv[1]);
	strcpy(dev.send_nics[0].dev_name, argv[1]);
	times = atoi(argv[2]);
	dev.queue_num = atoi(argv[3]);

	if(times == 0)
		forevery = 1;

	ret = init_queues(&dev);

	if(ret)
	{
		printf("init queue error\n");
		exit(-1);
	}

	while(times || forevery)
	{
		int index;
		r =  rand() % dev.queue_num;

		void * addr = get_receive_packet(r, &index);
		if(addr == NULL)
		{
		//	usleep(100);
			continue;
		}
		
		if(index == 0)
			printf("index is 0.\n");
		
		if(forward_receive_packet(dev.send_nics[0].nic_index, index))
			printf("forward packet %d error !\n", index);
		++count;
		--times;
		if(!(count % 100))
			printf("queue %4d forward %d packets !\n", r, count);
	}
	sleep(10);
	release_queues();
	exit(0);
}
