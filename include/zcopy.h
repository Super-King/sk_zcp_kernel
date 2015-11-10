#ifndef _ZCOPY_H_
#define _ZCOPY_H_

#ifdef __cplusplus

extern "C"
{
#endif
#include <stdint.h>
#include <net/if.h>
#define NIC_COUNT 8

	struct nic
	{
		char dev_name[IFNAMSIZ];
		uint32_t nic_index;
	};
	struct request_devices 
	{
		struct nic recv_nics[NIC_COUNT];
		struct nic send_nics[NIC_COUNT];
		uint32_t recv_count;
		uint32_t send_count;
		uint64_t recv_buffer_size;
		uint64_t send_buffer_size;
		uint32_t queue_num;
	};

#define MAX_QUEUE 16
	struct queue_status 
	{
		unsigned int queue_num;
		unsigned int total_per_queue[MAX_QUEUE];
		unsigned int free_per_queue[MAX_QUEUE];
	};

	int init_queues(struct request_devices *);

	int release_queues(void);

	void * get_receive_packet(int, int *);

	int drop_receive_packet(int);

	int forward_receive_packet(int, int);

	void * get_send_buffer(int *);

	int send_packet(int, int, int);

	int get_packet_length(int);

	int get_receive_queue_status(struct queue_status *status);

	/*
	 * description: catch a package from queue head.
	 * sid:         queue number will be used, from 0 sequence.
	 * return:      pointer for IP head, if not package return null.
	 */

#ifdef __cplusplus
}
#endif

#endif
