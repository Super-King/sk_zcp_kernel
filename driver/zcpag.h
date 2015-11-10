#ifndef _ZCPAG_H_
#define _ZCPAG_H_ 

#ifdef __cplusplus
extern "C"
{
#endif

#include <asm/ioctl.h>
#include <linux/types.h>
#include <linux/version.h>

#define MAX_QUEUES 16
//#define PACKET_SIZE (PAGE_SIZE / 2)
#define PACKET_SIZE PAGE_SIZE
#define NICS_COUNT 32

struct zcopy_info {
	int zcopy_fd;
	int thread_num;   //queue count
	__u64 rx_size;
	__u64 rx_ht_size;
	__u64 wx_size;
	__u64 wx_ht_size;
	int recv_nic[NICS_COUNT];
	int send_nic[NICS_COUNT];
	int recv_nic_num;
	int send_nic_num;
	int initialized;
};
#define ZCOPY_MAP_INIT _IOWR('Z', 1, struct zcopy_info)
#define ZCOPY_MAP_RX _IO('Z', 2)
#define ZCOPY_MAP_WX _IO('Z', 3)
#define ZCOPY_MAP_HT_RX _IO('Z', 4)
#define ZCOPY_MAP_HT_WX _IO('Z', 5)
#define ZCOPY_START_WORK _IO('Z', 6)

#define FROMKERNEL  0x81284
#define FROMUSER    0x84281

struct sk_zcopy 
{
	/* These two members must be first. */
	struct sk_zcopy         *next;
	struct sk_zcopy         *prev;
	__u32                   magic;
	__u32                   index;
	__u32                   len;
	__u32                   truesize;
	__u32                   queue_index;
	__u32                   nic_index;
	__u32                   usage;
	unsigned char           *virt_data;
	unsigned char           *orig_data;
	void                    (*free_zkb)(struct sk_zcopy *);
	void                    * ptr_skb[0];
};
//PAGESIZE 4096 as packet space I use 596 as metadata 
#define DATA_OFFSET 596
#define H_MAX_POOL_BUCKET 6
struct zcopy_buckets {
	__u32 zkb_in;
	__u32 zkb_out;
	__u32 drop_count;
	__u32 stop_queue;
	void * zkb_bucket_ptr[H_MAX_POOL_BUCKET]; //default 4M per bucket.
};

struct shared_hash_table {
	__u32 hash_table_size;
	__u32 hash_count;  //queue count from user config
	__u32 zkb_count_per_bucket;
	__u32 bucket_count_per_queue;
	__u32 zkb_bucket_size;
	__u32 zkb_bucket_order;
	__u32 zkb_count_per_queue;
	__u32 start_index;
	__u64 zkb_count;
	struct zcopy_buckets head[0];
};

#ifdef __cplusplus
}
#endif

#endif
