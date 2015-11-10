#ifndef ZERO_COPY_CDEV_H_
#define ZERO_COPY_CDEV_H_
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/list.h>
#include <linux/device.h>
#include <linux/proc_fs.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/uaccess.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/if_ether.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/kthread.h>

#include "zcpag.h"

#ifdef DEBUG
#define DebugPrintf(fmt, args...) printk(KERN_DEBUG "Debug: " fmt, ##args);
#else
#define DebugPrintf(fmt, args...)
#endif
#define ErrorPrintf(fmt, args...) printk(KERN_ERR "Error: " fmt, ##args);

#define ZEROCOPY_NAME "zcopy_rw"
#define ZEROCOPY_MAJOR 98
#define BUCKET_SIZE (PAGE_SIZE * 1024)

#define H_MAX_POOL_BUCKET 6

struct phy_zkb
{
	u32 bucket_count;
	u32 zkb_count_per_bucket;
	void ** bucket;
};
//core struct global
struct zcopy_rw_mem 
{
	u64 total_mem;

	u64 zkb_count;
	struct sk_buff_head head;
	
	u64 remap_count;
	u64 remap_bucket_size;
	u32 remap_order;
	u32 zkb_per_bucket;

	int nic[NICS_COUNT];
	int nics;
	int started;
	u32 start_index;
	struct phy_zkb pzkb;
	void ** remap_table;
};

struct thread_queue_info
{
	struct net_device * dev;
	u64 last_jiffies;
	u32 start_queue;
	u32 end_queue;
};
struct send_thread_info
{
	struct task_struct * send_task[MAX_QUEUES];
	struct task_struct * reclaim_task;
	struct thread_queue_info tqueue_info[NICS_COUNT];
};
#endif
