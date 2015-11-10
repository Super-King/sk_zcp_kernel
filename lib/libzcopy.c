#include <stdio.h>
#include <stdlib.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <linux/if_ether.h>
#include <sys/user.h>
#include <sys/sysinfo.h>

#include "libzcopy.h"

#ifdef DEBUG
#define D(fmt,args...) fprintf(stderr, "DEBUG: [%s - %d - %s]: "fmt, __FILE__, __LINE__, __func__, ##args)
#else
#define D(fmt,args...) 
#endif

#define E(fmt,args...) fprintf(stderr, "ERROR: [%s - %d - %s]: "fmt, __FILE__, __LINE__, __func__, ##args)

#define ZCOPY_FILE "/dev/zcopy_rw"

static pthread_mutex_t * rlock;
static pthread_mutex_t * wlock;
static struct zcopy_info zc;
static struct map_addr_info raddr;
static struct map_addr_info waddr;
static struct zcopy_hash_table rhash;
static struct zcopy_hash_table whash;

static inline struct sk_zcopy * get_zkb_by_index(__u32 zkb_index)
{
	struct sk_zcopy * zkb = NULL;
	struct zcopy_hash_table * zht = NULL;
	struct shared_hash_table * wh = whash.ht;
	struct shared_hash_table * rh = rhash.ht;
	__u32 index = 0;

	if(wh && ((zkb_index >= wh->start_index) && (zkb_index < (wh->start_index + wh->zkb_count))))
	{
		index = zkb_index - wh->start_index;
		zht = &whash;
	}
	else if(rh && ((zkb_index >= rh->start_index) && (zkb_index < (rh->start_index + rh->zkb_count))))
	{
		index = zkb_index - rh->start_index;
		zht = &rhash;
	}
	else
	{
		D("%s: zkb_index %u error !\n", __func__, zkb_index);
		return NULL;
	}

	zkb = zht->zkb[index];

#ifdef DEBUG
	if(((zkb->magic != FROMKERNEL) && (zkb->magic != FROMUSER)) || (zkb->index != zkb_index))
		D("%u skb %u magic %x error.\n", index, zkb->index, zkb->magic);
#endif
	return zkb;
}

//using skb index 0 -> usage to show write skb count;
static void update_zkb_count(void)
{
	struct sk_zcopy * zkb = get_zkb_by_index(0);
	zkb->usage = zcopy_zkb_queue_len(&whash.head);
}

static inline void free_zkb_to_pool(struct sk_zcopy *zkb)
{
	if(zkb == NULL)
		return;
	
	if(zkb->magic != FROMUSER)
	{
		D("error index %u.\n", zkb->index);
		return;
	}

	zkb->usage = 0;
	zcopy_zkb_queue_tail(&whash.head, zkb);
}

static int set_nic_up(char *dev, int up)
{
	struct ifreq iface;
	int fd, ret;

	if(dev == NULL) 
	{
		E("dev == NULL\n");
		goto err;
	}

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd <= 0) 
	{
		E("open socket failed: %s\n", dev);
		goto err;
	}

	strncpy(iface.ifr_name, dev, IFNAMSIZ);

	ret = ioctl(fd, SIOCGIFFLAGS, &iface);
	if(ret < 0) 
	{
		E("Get IFFLAGS failed: %s\n", dev);
		goto err_ioctl;
	}

	if(up)
		iface.ifr_flags |= IFF_UP | IFF_RUNNING;
	else
		iface.ifr_flags &= ~IFF_UP;

	ret = ioctl(fd, SIOCSIFFLAGS, &iface);
	if(ret < 0) 
	{
		E("Set IFFLAGS failed: %s\n", dev);
		goto err_ioctl;
	}
	D("Set NIC: %s into status %s.\n", dev, up ? "up":"down");

	close(fd);

	return 0;

err_ioctl:
	close(fd);
err:
	return -1;
}

static int set_nic_promisc(char *dev)
{
	struct ifreq iface;
	int fd, ret;

	if (dev == NULL) 
	{
		E("dev == NULL\n");
		goto err;
	}

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd <= 0) 
	{
		E("open socket failed: %s\n", dev);
		goto err;
	}

	strncpy(iface.ifr_name, dev, IFNAMSIZ);

	iface.ifr_flags |= IFF_PROMISC;
	
	ret = ioctl(fd, SIOCSIFFLAGS, &iface);
	if(ret < 0) 
	{
		E("Set IFFLAGS failed: %s\n", dev);
		goto err_ioctl;
	}
	D("Set NIC: %s into promisc.\n", dev);

	close(fd);

	return 0;

err_ioctl:
	close(fd);
err:
	return -1;
}

static int set_nics_promisc(struct request_devices * devs)
{
	int i = 0;
	for (i = 0; i < devs->recv_count; ++i)
		if(set_nic_promisc(devs->recv_nics[i].dev_name))
			return -1;
	return 0;
}

static int get_nic_index(char * dev)
{
	struct ifreq iface;
	int fd, ret;

	if(dev == NULL) 
	{
		E("dev == NULL\n");
		goto err;
	}

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(fd <= 0) 
	{
		E("open socket failed: %s\n", dev);
		goto err;
	}

	strncpy(iface.ifr_name, dev, IFNAMSIZ);

	//get nic name to ifindex mapping
	ret = ioctl(fd, SIOCGIFINDEX, &iface);
	if(ret < 0) 
	{
		E("%s GIFINDEX failed.\n", dev);
		goto err_ioctl;
	}
	D("NIC %s: index %d.\n", dev, iface.ifr_ifindex);

	close(fd);

	return iface.ifr_ifindex;

err_ioctl:
	close(fd);
err:
	return -1;

}
static int get_nics_index(struct request_devices * devs)
{
	int i = 0;

	if((devs->recv_count == 0) && (devs->send_count == 0))
	{
		E("NIC count is 0.");
		return -1;
	}

	for (i = 0; i < devs->recv_count; ++i)
	{
		devs->recv_nics[i].nic_index = get_nic_index(devs->recv_nics[i].dev_name);
		zc.recv_nic[i] = devs->recv_nics[i].nic_index;
		if(zc.recv_nic[i] < 0)
			return -1;
	}

	zc.recv_nic_num = devs->recv_count;

	for (i = 0; i < devs->send_count; ++i)
	{
		devs->send_nics[i].nic_index = get_nic_index(devs->send_nics[i].dev_name);
		zc.send_nic[i] = devs->send_nics[i].nic_index;
		if(zc.send_nic[i] < 0)
			return -1;
	}
	zc.send_nic_num = devs->send_count;
	return 0;
}
static int up_all_nics(struct request_devices * devs)
{
	int i = 0;
	for (i = 0; i < devs->recv_count; ++i)
		if(set_nic_up(devs->recv_nics[i].dev_name, 1))
			return -1;
	return 0;
}
static int down_all_nics(struct request_devices * devs)
{
	int i = 0;
	for (i = 0; i < devs->recv_count; ++i)
		if(set_nic_up(devs->recv_nics[i].dev_name, 0))
			return -1;
	return 0;
}
static void release_rw_mem(struct zcopy_hash_table * zht, struct map_addr_info * addrinfo)
{

	if(zht->zkb)
		free(zht->zkb);
	if(addrinfo->map_addr)
		munmap(addrinfo->map_addr, addrinfo->map_size);
	if(addrinfo->hash_addr)
		munmap(addrinfo->hash_addr, addrinfo->ht_map_size);
}
static int mmap_rw_mem(struct map_addr_info * addrinfo)
{
	int err = 0;
	err = ioctl(zc.zcopy_fd, addrinfo->map_flag, 0);
	if (err == -1)
	{
		E("ioctl ZCOPY_MAP_RX error\n");
		goto out;
	}

	addrinfo->map_addr = mmap(NULL, addrinfo->map_size, PROT_READ | PROT_WRITE, MAP_SHARED, zc.zcopy_fd, 0);
	if(addrinfo->map_addr == (void *)-1)
	{
		E("mmap rx memory failed\n");
		err = -1;
		addrinfo->map_addr = NULL;
		goto out;
	}

	err = ioctl(zc.zcopy_fd, addrinfo->ht_map_flag, 0);
	if(err == -1)
	{
		E("ioctl ZCOPY_MAP_HT_RX error\n");
		goto out;
	}

	addrinfo->hash_addr = mmap(NULL, addrinfo->ht_map_size, PROT_READ | PROT_WRITE, MAP_SHARED, zc.zcopy_fd, 0);
	if(addrinfo->hash_addr == (void *)-1)
	{
		E("mmap rx ht memory failed\n");
		err = -1;
		addrinfo->hash_addr = NULL;
		goto out;
	}
	return err;
out:
	return err;
}

static int init_queue_info(struct zcopy_hash_table * zht, struct map_addr_info * addinfo, int read)
{
	int i = 0;
	void * start_ptr = NULL;
	struct shared_hash_table * st;
	st = (struct shared_hash_table *)addinfo->hash_addr;
	zht->zb = st->head;

	start_ptr = addinfo->hash_addr + PAGE_SIZE;
	for(i = 0; i < st->hash_count; ++i)
	{
		zht->queue_ptr[i] = start_ptr;
		start_ptr += (st->zkb_bucket_size * st->bucket_count_per_queue);
#ifdef DEBUG
		if(((__u32 *)zht->queue_ptr[i])[0] != 0x19841022)
			D("zht->queue_ptr[%d], %x.\n", i, ((__u32 *)zht->queue_ptr[i])[0]);
		((__u32 *)zht->queue_ptr[i])[0] = 0;
#endif
	}

	
	zht->zkb = calloc(st->zkb_count, sizeof(struct sk_zcopy *));
	if(zht->zkb == NULL)
	{
		E("calloc sk_zcopy * error!\n");
		return -1;
	}

	zcopy_zkb_queue_head_init(&zht->head);
	start_ptr = addinfo->map_addr;
	for(i = 0; i < st->zkb_count; ++i)
	{
		zht->zkb[i] = (struct sk_zcopy *)start_ptr;
		zht->zkb[i]->virt_data = start_ptr + DATA_OFFSET;
		
		if((!read) && zht->zkb[i]->index)
			free_zkb_to_pool(zht->zkb[i]);
#ifdef DEBUG
		if((zht->zkb[i]->magic != (read ? FROMKERNEL : FROMUSER)) || ((i + st->start_index) != zht->zkb[i]->index))
			D("i %d skb index %d magic %x\n", i, zht->zkb[i]->index, zht->zkb[i]->magic);
#endif
		start_ptr += PACKET_SIZE;
	}
	zht->ht = st;
	return 0;
}

static void init_struct(struct zcopy_hash_table * zht, struct map_addr_info * addrinfo)
{
	memset(addrinfo, '\0', sizeof(struct map_addr_info));
	memset(zht, '\0', sizeof(struct zcopy_hash_table));
}

static int rw_disabled(int read)
{
	if(read && (zc.rx_size == 0))
	{
		D("read disabled !\n");
		return 1;
	}
	if(!read && (zc.wx_size == 0))
	{
		D("write disabled !\n");
		return 1;
	}
	return 0;
}

static int init_rw_queue(struct zcopy_hash_table * zht, struct map_addr_info * addrinfo, pthread_mutex_t ** lock, int read)
{
	int err = -1;
	int i = 0;
	init_struct(zht, addrinfo);

	if(rw_disabled(read))
		return 0;

	addrinfo->map_size = read ? zc.rx_size : zc.wx_size ;
	addrinfo->ht_map_size = read ? zc.rx_ht_size : zc.wx_ht_size;
	addrinfo->map_flag = read ? ZCOPY_MAP_RX : ZCOPY_MAP_WX;
	addrinfo->ht_map_flag = read ? ZCOPY_MAP_HT_RX : ZCOPY_MAP_HT_WX;

	err = mmap_rw_mem(addrinfo);
	if(err)
		goto err;

	err = init_queue_info(zht, addrinfo, read);
	if(err)
		goto err;

	*lock = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t) * zc.thread_num);
	if(*lock == NULL)
	{
		E("lock malloc memory failed.\n");
		err = -1;
		goto err;
	}
	for(i = 0; i < zc.thread_num; ++i)
	{
		if((err = pthread_mutex_init(&(*lock)[i], NULL)) != 0)
		{
			E("pthread mutex init failed.\n");
			goto err;
		}
	}
	D("%s: skb_count %llu, hash_count %u, bucket_count_per_queue %u.\n", read ? "read" : "write", zht->ht->zkb_count, \
			zht->ht->hash_count, zht->ht->bucket_count_per_queue);

	return 0;
err:
	release_rw_mem(zht, addrinfo);
	return err;
}

int init_queues(struct request_devices * devs)
{
	int err = 0;
	__u64 max_mem = 0;
	struct sysinfo s_info;

	if(zc.initialized == 1)
	{
		E("Cannot initialize queues twice\n");
		err = -1;
		goto init_err;
	}

	memset(&zc, '\0', sizeof(struct zcopy_info));

	if((err = get_nics_index(devs)) != 0)
	{
		E("get nics index error !\n");
		goto init_err;
	}
	
	err = down_all_nics(devs);
	if(err)
		goto init_err;
	
	if((err = sysinfo(&s_info)) != 0)
	{
		E("get system info error !\n");
		goto init_err;
	}

	max_mem = s_info.totalram * 30 / 100;

	zc.rx_size = devs->recv_buffer_size;
	zc.rx_size = (zc.rx_size << 20) < max_mem ? zc.rx_size << 20 : max_mem;

	zc.wx_size = devs->send_buffer_size;
	zc.wx_size = (zc.wx_size << 20) < max_mem ? zc.wx_size << 20 : max_mem;
	zc.thread_num = devs->queue_num;

	if(!zc.thread_num || (zc.thread_num > MAX_QUEUES))
	{
		err = -1;
		E("queue count error %d.\n", devs->queue_num);
		goto init_err;
	}
	
	zc.zcopy_fd = open(ZCOPY_FILE, O_RDWR);
	if(zc.zcopy_fd == -1) 
	{
		E("Cannot open dev file: " ZCOPY_FILE "\n");
		err = -1;
		goto init_err;
	}

	err = ioctl(zc.zcopy_fd, ZCOPY_MAP_INIT, &zc);
	if(err)
	{
		E("ioctl ZCOPY_MAP_INIT error\n");
		goto ioctl_err;
	}

	err = init_rw_queue(&rhash, &raddr, &rlock, 1);
	if(err)
		goto ioctl_err;

	err = init_rw_queue(&whash, &waddr, &wlock, 0);
	if(err)
		goto init_write_queue_err;

	err = ioctl(zc.zcopy_fd, ZCOPY_START_WORK, 0);
	if(err)
	{
		E("ioctl ZCOPY_START_WORK error\n");
		goto start_work_err;
	}

	update_zkb_count();
	
	err = up_all_nics(devs);
	if(err)
		goto start_work_err;

	err = set_nics_promisc(devs);
	if(err)
		goto start_work_err;

	zc.initialized = 1;
	return 0;

start_work_err:
	release_rw_mem(&whash, &waddr);
init_write_queue_err:
	release_rw_mem(&rhash, &raddr);
ioctl_err:
	close(zc.zcopy_fd);
init_err:
	return err;
}

int release_queues(void)
{
	if (zc.initialized != 1) {
		E("no initialize queues\n");
		return -1;
	}

	if(rlock)
		free(rlock);
	if(wlock)
		free(wlock);
	release_rw_mem(&rhash, &raddr);
	release_rw_mem(&whash, &waddr);
	close(zc.zcopy_fd);
	zc.initialized = 0;
	return 0;
}

static inline int packet_readable(__u32 num)
{
	struct zcopy_buckets * buckets = rhash.zb;
	struct shared_hash_table * rh = rhash.ht;
	__u32 out, in;

	in = buckets[num].zkb_in % rh->zkb_count_per_queue;
	out = buckets[num].zkb_out % rh->zkb_count_per_queue;
	if(out == in)
		return 0;
	return 1;
}
void * get_receive_packet(int queue_index, int * index)
{
	__u64 zkb_index = 0;
	__u64 * index_ptr = NULL;
	__u64 out = 0;
	pthread_mutex_t * lock = &rlock[queue_index];
	struct sk_zcopy * zkb = NULL;
	struct shared_hash_table * rh = rhash.ht;
	struct zcopy_buckets * buckets = rhash.zb;

	if(queue_index > rh->hash_count)
	{
		E("queue index %d > max %d.\n", queue_index, rh->hash_count);
		return NULL;
	}

	pthread_mutex_lock(lock);
	if(!packet_readable(queue_index))
		goto out;

	index_ptr = (__u64 *)rhash.queue_ptr[queue_index];
	out = buckets[queue_index].zkb_out % rh->zkb_count_per_queue;

	zkb_index = index_ptr[out];

#ifdef DEBUG
	if((zkb_index == 0) || (whash.ht && (zkb_index > whash.ht->start_index)))
	{
		E("skb index = %llu > %u, queue %d out %llu, in %u.\n", \
				zkb_index, whash.ht->start_index, queue_index, out, buckets[queue_index].zkb_in);
		goto err;
	}
#endif
	zkb = get_zkb_by_index(zkb_index);
	if(zkb == NULL)
		goto err;

	if((zkb->magic != FROMKERNEL) || (zkb->queue_index != queue_index))
	{
		D("skb magic %x error or queue index %d != skb->queue_index %d\n", zkb->magic, queue_index, zkb->queue_index);
		zkb = NULL;
		goto err;
	}

	zkb->usage = 1;
	*index = zkb_index;
err:
	++buckets[queue_index].zkb_out;
out:
	pthread_mutex_unlock(lock);
	return zkb ? zkb->virt_data : NULL;
}
int drop_receive_packet(int index)
{
	struct sk_zcopy * zkb = NULL;
	zkb = get_zkb_by_index(index);

	if(zkb == NULL)
		return -1;
#ifdef DEBUG
	if((zkb->magic != FROMKERNEL) || (zkb->usage != 1))
	{
		E("the packet has not been used. index %d. or it is not come from receive queue !\n,", \
				zkb->index);
		return -1;
	}
#endif
	zkb->usage = 0;
	return 0;
}
static inline int packet_writable(__u32 num)
{
	struct zcopy_buckets * buckets = whash.zb;
	struct shared_hash_table * wh = whash.ht;
	__u32 in, out;
	in = (buckets[num].zkb_in + 1) % wh->zkb_count_per_queue;
	out = buckets[num].zkb_out % wh->zkb_count_per_queue;
	
	if(in == out)
		return 0;
	return 1;
}
static int __send_packet(int queue_index, int index)
{
	__u64 * index_ptr = NULL;
	__u64 old_zkb_index = 0;
	__u32 in = 0; 
	int ret = -1;
	struct sk_zcopy * old_zkb = NULL;
	pthread_mutex_t * lock = &wlock[queue_index];
	struct shared_hash_table * wh = whash.ht;
	struct zcopy_buckets * buckets = whash.zb;
	
	if((wh == NULL) || (queue_index > wh->hash_count))
	{
		E("No enable send packet function.\n");
		E("queue index %d > max %d.\n", queue_index, MAX_QUEUES);
		return ret;
	}

	pthread_mutex_lock(lock);
	if(!packet_writable(queue_index))
	{
		++buckets[queue_index].drop_count;
		goto not_writable;
	}

	index_ptr = (__u64 *)whash.queue_ptr[queue_index];
	in = buckets[queue_index].zkb_in % wh->zkb_count_per_queue;

	old_zkb_index = index_ptr[in];

	if(old_zkb_index == 0)
		goto plus_zkb_in;

	old_zkb = get_zkb_by_index(old_zkb_index);
	
	if(old_zkb && old_zkb->magic == FROMKERNEL)
		goto plus_zkb_in;

	if(old_zkb && old_zkb->usage)
	{
		++buckets[queue_index].drop_count;
		goto not_writable;
	}

	free_zkb_to_pool(old_zkb);

plus_zkb_in:
	ret = 0;
	index_ptr[in] = index;
	++buckets[queue_index].zkb_in;
not_writable:
	pthread_mutex_unlock(lock);
	return ret;
}
int forward_receive_packet(int nic_index, int index)
{
	struct sk_zcopy * zkb = get_zkb_by_index(index);

	if((zkb == NULL) || (index == 0))
	{
		E("%s: zkb is null or index %d error.\n", __func__, index);
		return -1;
	}

	if((zkb->magic != FROMKERNEL) || zkb->usage != 1)
	{
		E("%s must use a packet that from get_one_packet !\n", __func__);
		E("zkb->index %d, magic, %x, usage %d.\n", zkb->index, zkb->magic, zkb->usage);
		return -1;
	}
	update_zkb_count();

	zkb->nic_index = nic_index;
	if(__send_packet(zkb->queue_index, index))
	{
		zkb->usage = 0;
		return -1;
	}
	return 0;
}

void * get_send_buffer(int * index)
{
	struct sk_zcopy * zkb = NULL;

	zkb = zcopy_zkb_dequeue(&whash.head);
	if(zkb)
	{
		if(zkb->magic != FROMUSER)
		{
			D("%s: skb index %u error.\n", __func__, zkb->index);
			return NULL;
		}
		zkb->next = (void*)0x19810828;
		zkb->len = 0;
		*index = zkb->index;
		update_zkb_count();
	}
	return zkb ? zkb->virt_data : NULL;
}

int send_packet(int nic_index, int index, int size)
{
	struct sk_zcopy * zkb = NULL;
	struct shared_hash_table * wh = whash.ht;

	zkb = get_zkb_by_index(index);
	if((zkb == NULL) || (index == 0))
	{
		E("%s: zkb is null or index %d error.\n", __func__, index);
		return -1;
	}

	if((size > 1514) || (wh == NULL))
	{
		E("%s: data packet len %d error.\n", __func__, size);
		E("No enable send packet function,\n");
		return -1;
	}
	
	if((zkb->next != (void*)0x19810828) || (zkb->magic != FROMUSER))
	{
		D("you got wrong packet index %u or packet come from kernel %x !\n",\
				index, zkb->magic);
		return -1;
	}

	//just one queue is enough ?
	zkb->nic_index = nic_index;
	zkb->queue_index = index % wh->hash_count;
	zkb->len = size < ETH_ZLEN ? ETH_ZLEN : size;
	zkb->next = zkb->prev;
	if(__send_packet(zkb->queue_index, index))
	{
		free_zkb_to_pool(zkb);
		return -1;
	}
	return 0;
}

int get_packet_length(int index)
{
	struct sk_zcopy * zkb;
	
	zkb = get_zkb_by_index(index);

	if((zkb->magic != FROMUSER) && (zkb->magic != FROMKERNEL))
	{
		D("%s: skb locate error !\n", __func__);
		return -1;
	}
	return zkb->len;
}

int get_receive_queue_status(struct queue_status *status)
{
	struct shared_hash_table * rh = rhash.ht;
	struct zcopy_buckets * buckets = rhash.zb;
	unsigned int i = 0;

	if(rh == NULL)
		return -1;

	for(i = 0; i < status->queue_num; ++i)
	{
		unsigned int in, out, free_count;
		in = buckets[i].zkb_in % rh->zkb_count_per_queue;
		out = buckets[i].zkb_out % rh->zkb_count_per_queue;
		if(in >= out)
			free_count = rh->zkb_count_per_queue - (in - out);
		else
			free_count = out - in;

		status->total_per_queue[i] = rh->zkb_count_per_queue;
		status->free_per_queue[i] = free_count;
	}
	return 0;
}
