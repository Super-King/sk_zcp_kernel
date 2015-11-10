#include "zero_copy_rw.h"

static u64 protocol_flag = 0;
#define ZERO_ARP  0x01
#define ZERO_RARP 0x02
#define ZERO_ICMP 0x04
#define ZERO_TCP  0x08
#define ZERO_UDP  0x10
#define ZERO_ALL  0x1f

static DEFINE_SPINLOCK(open_lock);
static int open_count = 0;

#define MAP_RX_MEM 0x01
#define MAP_WX_MEM 0x02
#define MAP_RXHT_MEM 0x04
#define MAP_WXHT_MEM 0x08
static int map_type = 0;

static struct sk_buff_head usage_head;
static spinlock_t rlock[MAX_QUEUES];
static struct zcopy_rw_mem zcopy_rmem;
static struct zcopy_rw_mem zcopy_wmem;
static struct shared_hash_table  * rhash_table;
static struct shared_hash_table  * whash_table;
static u32 total_count = 0;

typedef struct sk_buff * (*alloc_zcp_zkb)(struct net_device *, int *);
typedef void (*free_zcp_zkb)(struct sk_buff *, int *);
typedef void (*deliver_zcp_zkb)(struct sk_buff *, int *);
extern void register_zero_copy_alloc_release_fun(alloc_zcp_zkb, free_zcp_zkb);
extern void register_zero_copy_deliver_fun(deliver_zcp_zkb);
extern void unregister_zero_copy_alloc_release_fun(void);
extern void unregister_zero_copy_deliver_fun(void);

static inline __be16 get_type_eth(const struct sk_zcopy * zkb)
{
	struct ethhdr * eth = (struct ethhdr *)zkb->orig_data;
	return eth->h_proto;
}

static inline int rw_disabled(struct zcopy_info * zi, int read)
{
	if(read && (zi->rx_size == 0))
		return 1;
	if(!read && (zi->wx_size == 0))
		return 1;
	return 0;
}

static inline struct sk_buff * convert_sk_buff(struct sk_zcopy * zkb)
{
	return (struct sk_buff *)zkb->ptr_skb;
}
static inline struct sk_zcopy * convert_sk_zcopy(struct sk_buff * skb)
{
	return container_of((void*)skb, struct sk_zcopy, ptr_skb);
}
static inline int is_zcopy_packet(struct sk_buff * skb)
{
	struct sk_zcopy * zkb = convert_sk_zcopy(skb);

	if((zkb->magic == FROMKERNEL) || (zkb->magic == FROMUSER))
		return 1;
	return 0;
}

static inline void start_zero_copy(void)
{
	zcopy_rmem.started = zcopy_wmem.started = 1;
}
static inline int zkb_index_error(struct zcopy_rw_mem * mem, u32 index)
{
	if(index == 0)
		return -1;
	if((index < mem->start_index) || (index >= mem->start_index + mem->zkb_count))
		return -1;
	return 0;
}
static inline void stop_zero_copy(void)
{
	zcopy_rmem.started = zcopy_wmem.started = 0;
}
static inline int zkb_from_kernel(struct sk_zcopy * zkb)
{
	return zkb->magic == FROMKERNEL;
}
static inline void wait_zkb_to_reclaim(struct sk_zcopy * zkb)
{
	if(zkb == NULL)
		return;

	if(!zkb_from_kernel(zkb))
	{
		DebugPrintf("%s: error %u index magic %x !\n", __func__, zkb->index, zkb->magic);
		return;
	}
	skb_queue_tail(&usage_head, convert_sk_buff(zkb));
}
static void free_user_zkb(struct sk_zcopy * zkb)
{
	if(zkb == NULL)
		return;
	zkb->usage = 0;
}
static void free_kernel_zkb(struct sk_zcopy * zkb)
{
	if(zkb == NULL)
		return;

#ifdef DEBUG
	if(zkb_index_error(&zcopy_rmem, zkb->index))
	{
		DebugPrintf("%s: skb index %u error, magic %x.\n", __func__, \
				zkb->index, zkb->magic);
		return;
	}
	if(!zkb_from_kernel(zkb))
	{
		DebugPrintf("%s: error %u index magic %x !\n", __func__, zkb->index, zkb->magic);
		return;
	}
#endif
	zkb->usage = 0;
	skb_queue_tail(&zcopy_rmem.head, convert_sk_buff(zkb));
}

static void reclaim_usaged_zkb(int times)
{
	struct sk_buff * skb;
	struct sk_zcopy * zkb;

	while(times--)
	{
		skb = skb_dequeue(&usage_head);
		if(!skb)
			break;
		
		zkb = convert_sk_zcopy(skb);
		if(zkb->usage)
			wait_zkb_to_reclaim(zkb);
		else
			free_kernel_zkb(zkb);
	}
}
static inline struct sk_buff * alloc_regular_skb(struct net_device *dev, unsigned int length)
{
	struct sk_buff * skb;

	skb = alloc_skb(length + NET_SKB_PAD + NET_IP_ALIGN, GFP_ATOMIC);
	if(NET_IP_ALIGN && skb) 
	{
		skb_reserve(skb, NET_IP_ALIGN + NET_SKB_PAD);
		skb->dev = dev;
	}
	return skb;
}
static inline void convert_and_init_sk_zcopy(struct sk_zcopy * zkb, struct net_device * dev)
{
	struct sk_buff * skb = convert_sk_buff(zkb);
	if(NET_IP_ALIGN) //after alloced skb the kernel will call sbk_reserve to reserve NET_IP_ALIGN
		skb->data = zkb->orig_data - NET_IP_ALIGN;
	skb->head = skb->data;
	skb_reset_tail_pointer(skb);
	skb->truesize = zkb->truesize;
	atomic_set(&skb->users, 1);
	skb->end = skb->tail + zkb->truesize;
	skb->len = 0;
	skb->dev = dev;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
	skb->mac_header = ~0U;
#endif
}
static struct sk_buff * _alloc_zcopy_zkb(struct net_device *dev)
{
	struct sk_buff * skb = NULL;
	struct sk_zcopy * zkb = NULL;

	skb = skb_dequeue(&zcopy_rmem.head);
	if(skb)
	{
		zkb = convert_sk_zcopy(skb);
		zkb->len = 0;
		zkb->free_zkb = free_kernel_zkb;
		convert_and_init_sk_zcopy(zkb, dev);
	}
	return skb;
}
struct sk_buff * alloc_zcopy_zkb(struct net_device *dev, int * err)
{
	u32 i = 0;
	int ifindex = dev->ifindex;
	struct sk_buff * skb = NULL;
	if(zcopy_rmem.started)
	{
		for(i = 0; i < zcopy_rmem.nics; ++i)
		{
			if(ifindex == zcopy_rmem.nic[i])
			{
				skb = _alloc_zcopy_zkb(dev);
#ifdef DEBUG
				if(skb)
				{
					if(!zkb_from_kernel(convert_sk_zcopy(skb)) || zkb_index_error(&zcopy_rmem, convert_sk_zcopy(skb)->index))
						DebugPrintf("%s: skb type error, index %u, magic %x.\n", __func__, \
								convert_sk_zcopy(skb)->index, convert_sk_zcopy(skb)->magic);
				}
#endif
				err = 0;
				return skb;
			}
		}
	}
	*err = -1;
	return NULL;
}
EXPORT_SYMBOL(alloc_zcopy_zkb);

void free_zcopy_zkb(struct sk_buff * skb, int * err)
{
	if(is_zcopy_packet(skb))
	{
		struct sk_zcopy * zkb = convert_sk_zcopy(skb);
		zkb->free_zkb(zkb);
		*err = 0;
	}
	else
		*err = -1;
	return;
}

EXPORT_SYMBOL(free_zcopy_zkb);

static inline u32 get_hash_value(struct sk_zcopy * zkb)
{
	__be16 protocol = get_type_eth(zkb);
	u32 hash_count = rhash_table->hash_count;
	struct iphdr * iph;
	void * ptr = (void *)zkb->orig_data + sizeof(struct ethhdr);

	switch(protocol)
	{
		case __constant_htons(ETH_P_IP):
		case __constant_htons(ETH_P_IPV6):
			iph = (struct iphdr *)ptr;
			zkb->queue_index = jhash_2words(iph->saddr, iph->daddr, 100) % hash_count;
			break;
		default:
			zkb->queue_index = jhash_2words(*((u32 *)ptr), *((u32*)(ptr + sizeof(u32))), 100) % hash_count;
			break;
	}
	return zkb->queue_index;
}
static u64 * get_ptr_position(struct shared_hash_table * ht, u32 queue, u32 pos)
{
	u64 * ptr;
	struct zcopy_buckets * zb = ht->head;
	u32 pool_num, offset_of_pool;
	pool_num = (pos / ht->zkb_count_per_bucket) % ht->bucket_count_per_queue;
	offset_of_pool = pos % ht->zkb_count_per_bucket;
	ptr = zb[queue].zkb_bucket_ptr[pool_num];
	return &ptr[offset_of_pool];
}

static inline struct sk_zcopy * get_zkb_by_index(u32 zkb_index)
{
	u32 bucket_num, index;
	u32 bucket_offset;
	struct phy_zkb * phy;
	struct sk_zcopy ** ptr;

	if((zkb_index >= zcopy_wmem.start_index) && (zkb_index < (zcopy_wmem.start_index + zcopy_wmem.zkb_count)))
	{
		index = zkb_index - zcopy_wmem.start_index;
		phy = &zcopy_wmem.pzkb;
	}
	else if((zkb_index >= zcopy_rmem.start_index) && (zkb_index < (zcopy_rmem.start_index + zcopy_rmem.zkb_count))) 
	{
		index = zkb_index - zcopy_rmem.start_index;
		phy = &zcopy_rmem.pzkb;
	}
	else
	{
		DebugPrintf("%s: skb index %u. error !\n", __func__, zkb_index);
		return NULL;
	}

	bucket_num = (index / phy->zkb_count_per_bucket) % phy->bucket_count;
	bucket_offset = index % phy->zkb_count_per_bucket;

	ptr = phy->bucket[bucket_num];
	return ptr[bucket_offset];
}
static inline int packets_writable(u32 num)
{
	u32 zkb_in, zkb_out;
	zkb_in = (rhash_table->head[num].zkb_in + 1) % (rhash_table->zkb_count_per_queue);
	zkb_out = rhash_table->head[num].zkb_out % (rhash_table->zkb_count_per_queue);

	if(zkb_in == zkb_out)
		return 0;
	return 1;

}
static inline int validate_zkb_correctness(struct sk_zcopy * zkb)
{
	if(zcopy_rmem.started == 0)
		return -1;

	if(!zkb_from_kernel(zkb) || zkb_index_error(&zcopy_rmem, zkb->index))
	{
		DebugPrintf("%s skb->index %u error, magic %x skb addr %llx.\n", __func__, \
				zkb->index, zkb->magic, (u64)zkb);
		return -1;
	}
	zkb->len = convert_sk_buff(zkb)->len;
	//correct
	return 0;
}
static inline u32 free_slot_count(void)
{
	if(rhash_table)
		return (rhash_table->zkb_count - rhash_table->zkb_count_per_queue * rhash_table->hash_count) - 100;
	return 0;
}

static inline void call_netif_receive_skb(struct sk_zcopy * zkb)
{
	u32 deliver_packet = 0;
	struct sk_buff * skb = NULL;
	struct sk_buff * newskb = NULL;

	switch(get_type_eth(zkb))
	{
		case __constant_htons(ETH_P_IP):
		{
			struct iphdr * iph = (struct iphdr *)(zkb->orig_data + ETH_HLEN);
			switch(iph->protocol)
			{
				case IPPROTO_ICMP:
					if(protocol_flag & ZERO_ICMP)
						deliver_packet = 1;
					break;
				case IPPROTO_TCP:
					if(protocol_flag & ZERO_TCP)
						deliver_packet = 1;
					break;
				case IPPROTO_UDP:
					if(protocol_flag & ZERO_UDP)
						deliver_packet = 1;
					break;
				default:
					break;
			}
		}
		break;
		case __constant_htons(ETH_P_ARP):
			if(protocol_flag & ZERO_ARP)
				deliver_packet = 1;
			break;
		case __constant_htons(ETH_P_RARP):
			if(protocol_flag & ZERO_RARP)
				deliver_packet = 1;
			break;
		default:
			break;
	}
	
	if(!deliver_packet)
		return;
	
	skb = convert_sk_buff(zkb);
	
	//eth_type_trans will skb_pull the skb.
	newskb = alloc_regular_skb(skb->dev, skb->len + ETH_HLEN);
	if(newskb)
	{
		memcpy(skb_put(newskb, skb->len + ETH_HLEN), zkb->orig_data, skb->len + ETH_HLEN);
		skb_record_rx_queue(newskb, zkb->queue_index);
		newskb->protocol = eth_type_trans(newskb, skb->dev);
		netif_receive_skb(newskb);
	}
}

static void deliver_zkb_to_app_fifo(struct sk_zcopy * zkb)
{
	u32 queue_num = 0;
	u32 zkb_pos = 0;
	u64 old_zkb_index;
	struct sk_zcopy * old_zkb = NULL;
	u64 * ptr = NULL;
	unsigned long flags;

	if(validate_zkb_correctness(zkb))
		return;

	queue_num = get_hash_value(zkb);
	
	if(protocol_flag)
		call_netif_receive_skb(zkb);

	spin_lock_irqsave(&rlock[queue_num], flags);
	if(!packets_writable(queue_num))
	{
		++rhash_table->head[queue_num].drop_count;
		free_kernel_zkb(zkb);
		goto not_writable;
	}

	zkb_pos = rhash_table->head[queue_num].zkb_in;
	ptr = get_ptr_position(rhash_table, queue_num, zkb_pos);
	
	old_zkb_index = *ptr;

	if(old_zkb_index == 0)
		goto plus_zkb_in;

	old_zkb = get_zkb_by_index(old_zkb_index);

	if(old_zkb == NULL)
		goto plus_zkb_in;

	if(old_zkb->usage)
	{
		if(skb_queue_len(&usage_head) < free_slot_count())
			wait_zkb_to_reclaim(old_zkb);
		else
		{
			++rhash_table->head[queue_num].drop_count;
			free_kernel_zkb(zkb);
			goto not_writable;
		}
	}
	else
		free_kernel_zkb(old_zkb);

plus_zkb_in:
	*ptr = zkb->index;
	++rhash_table->head[queue_num].zkb_in;
not_writable:
	spin_unlock_irqrestore(&rlock[queue_num], flags);
	return;
}

void deliver_zcopy_zkb(struct sk_buff * skb, int * err)
{
	if(is_zcopy_packet(skb))
	{
		deliver_zkb_to_app_fifo(convert_sk_zcopy(skb));
		*err = 0;
	}
	else
		*err = -1;
	return;
}
EXPORT_SYMBOL(deliver_zcopy_zkb);

static void free_rw_remap_mem(struct zcopy_rw_mem * mem)
{
	int i;
	
	if(mem->remap_table == NULL)
		return;

	for(i = 0; i < mem->remap_count; ++i)
	{
		if(mem->remap_table[i])
		{
			memset(mem->remap_table[i], '\0', mem->remap_bucket_size);
			free_pages((unsigned long)mem->remap_table[i], mem->remap_order);
		}
	}
	kfree(mem->remap_table);
	memset(mem, '\0', sizeof(struct zcopy_rw_mem));
}

static void init_zcopy_remap_struct(struct zcopy_rw_mem * mem)
{
	memset(mem, '\0', sizeof(struct zcopy_rw_mem));
	mem->remap_bucket_size = BUCKET_SIZE;
}
static void free_phy_zkb_ptr(struct zcopy_rw_mem * mem)
{
	u32 i = 0;
	struct phy_zkb * phy;
	phy = &mem->pzkb;
	for(i = 0; i < phy->bucket_count; ++i)
		if(phy->bucket[i])
			free_pages((unsigned long)phy->bucket[i], get_order(BUCKET_SIZE));
	kfree(phy->bucket);
}
static int alloc_phy_zkb_ptr(struct zcopy_rw_mem * mem, u64 zkb_count)
{
	struct phy_zkb * phy;
	u32 buckets = 0, i = 0;
	u64 total_ptr_size = zkb_count * sizeof(struct sk_zcopy *);
	
	phy = &mem->pzkb;
	buckets = total_ptr_size / BUCKET_SIZE;
	++buckets;

	phy->bucket_count = buckets;
	phy->zkb_count_per_bucket = BUCKET_SIZE / sizeof(struct sk_zcopy *);
	phy->bucket = kzalloc(phy->bucket_count * sizeof(void *), GFP_KERNEL);

	DebugPrintf("phy: bucket_count %u, zkb_count_per_bucket %u\n", phy->bucket_count, phy->zkb_count_per_bucket);
	if(phy->bucket == NULL)
	{
		ErrorPrintf("alloc failure bucket %u.\n", phy->bucket_count);
		return -1;
	}

	for(i = 0; i < phy->bucket_count; ++i)
	{
		phy->bucket[i] = (void*)__get_free_pages(GFP_KERNEL, get_order(BUCKET_SIZE));
		if(phy->bucket[i] == NULL)
			goto alloc_phy_bucket_err;
		memset(phy->bucket[i], '\0', BUCKET_SIZE);
	}

	return 0;

alloc_phy_bucket_err:
	ErrorPrintf("alloc phy bucket memory failed!\n");
	free_phy_zkb_ptr(mem);
	return -1;
}
static void init_phy_zkb_ptr(struct zcopy_rw_mem * mem, struct sk_zcopy * zkb)
{
	u32 bucket_num, index;
	u32 bucket_offset;
	struct phy_zkb * phy;
	struct sk_zcopy ** ptr;
	phy = &mem->pzkb;
	
	index = zkb->index - mem->start_index;

	bucket_num = (index / phy->zkb_count_per_bucket) % phy->bucket_count;
	bucket_offset = index % phy->zkb_count_per_bucket;

	ptr = phy->bucket[bucket_num];
	ptr[bucket_offset] = zkb;
}

static int alloc_init_rw_zcopy_zkb(struct zcopy_rw_mem * mem, int read)
{
	u32 i = 0, j = 0;
	
	mem->zkb_count = mem->total_mem / PACKET_SIZE;
	mem->zkb_per_bucket = mem->remap_bucket_size / PACKET_SIZE;
	skb_queue_head_init(&mem->head);

	if(alloc_phy_zkb_ptr(mem, mem->zkb_count))
		return -1;

	mem->start_index = total_count;
	for(i = 0; i < mem->remap_count; ++i)
	{
		for(j = 0; j < mem->zkb_per_bucket; ++j)
		{
			struct sk_zcopy * zkb = (struct sk_zcopy *)(mem->remap_table[i] + (j * PACKET_SIZE));
			zkb->magic = read ? FROMKERNEL : FROMUSER;
			zkb->index = total_count++;

			zkb->orig_data = mem->remap_table[i] + (j * PACKET_SIZE) + DATA_OFFSET;
			zkb->truesize = PACKET_SIZE - DATA_OFFSET - SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
			
			init_phy_zkb_ptr(mem, zkb);
			if(zkb->index && read) // jump over 0 index and enqueue for read
				free_kernel_zkb(zkb);
		}
	}

	DebugPrintf("%s: total skb count %u, %llu, total_count %u.\n", (read ? "read" : "write"), \
			skb_queue_len(&mem->head), mem->zkb_count, total_count);

	return 0;
}

static int alloc_rw_remap_mem(struct zcopy_rw_mem * mem, u64 mem_size)
{
	u32 i = 0;

	init_zcopy_remap_struct(mem);

	if(mem_size < (512 << 20)) //minimal 512M memory
		mem_size = 512 << 20;

	mem->remap_order = get_order(mem->remap_bucket_size);
	mem->remap_count = mem_size / mem->remap_bucket_size;
	mem->total_mem = mem->remap_count * mem->remap_bucket_size;

	mem->remap_table = kzalloc(sizeof(mem->remap_table) * mem->remap_count, GFP_KERNEL);

	if(mem->remap_table == NULL)
	{
		ErrorPrintf("alloc mem for remap table failure");
		goto remap_table_err;
	}
	for(i = 0; i < mem->remap_count; ++i)
	{
		mem->remap_table[i] = (void*)__get_free_pages(GFP_KERNEL, mem->remap_order);
		if(mem->remap_table[i] == NULL)
			goto remap_mem_err;
		memset(mem->remap_table[i], '\0', mem->remap_bucket_size);
	}

	DebugPrintf("%s remap_order %d, remap_count %llu, remap_bucket_size %llu, total_mem %llu\n", __func__, 
			mem->remap_order, mem->remap_count, mem->remap_bucket_size, mem->total_mem);
	return 0;

remap_mem_err:
	ErrorPrintf("alloc mem for remap failure");
	free_rw_remap_mem(mem);
remap_table_err:
	return -1;
}

static void free_zkb_index_ptr(void)
{
	free_phy_zkb_ptr(&zcopy_rmem);
	free_phy_zkb_ptr(&zcopy_wmem);
	return;
}
static int init_rw_zcopy_mem(struct zcopy_info * zi, struct zcopy_rw_mem * mem, int read)
{
	int ret = -1;
	int i = 0;

	if(rw_disabled(zi, read))
		return 0;

	ret = alloc_rw_remap_mem(mem, (read ? zi->rx_size : zi->wx_size));
	if (ret)
		goto alloc_rx_remap_err;

	ret = alloc_init_rw_zcopy_zkb(mem, read);
	if (ret)
		goto alloc_init_rx_zkb_err;

	if(read)
	{
		zi->rx_size = mem->total_mem;
		mem->nics = zi->recv_nic_num;
		for(i = 0; i < zi->recv_nic_num; ++i)
		{
			mem->nic[i] = zi->recv_nic[i];
			DebugPrintf("%s: count %d: index %d netcard will be enabled zero copy.\n", \
					read ? "read" : "write", mem->nics, mem->nic[i]);
		}
	}
	else
	{
		zi->wx_size = mem->total_mem;
		mem->nics = zi->send_nic_num;
		for(i = 0; i < zi->send_nic_num; ++i)
		{
			mem->nic[i] = zi->send_nic[i];
			DebugPrintf("%s: count %d: index %d netcard will be enabled zero copy.\n", \
					read ? "read" : "write", mem->nics, mem->nic[i]);
		}
	}
	return ret;

alloc_init_rx_zkb_err:
	free_rw_remap_mem(mem);
alloc_rx_remap_err:
	return ret;
}

ssize_t zerocopy_rw_read(struct file *filp, char *buf, size_t count, loff_t *f_pos)
{
	        return 0;
}
ssize_t zerocopy_rw_write(struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
	        return 0;
}
static int zerocopy_rw_open(struct inode *inode, struct file *filp)
{
	int err = -EBUSY;
	spin_lock(&open_lock);
	if(open_count == 0)
	{
		++open_count;
		total_count = 0;
		protocol_flag = 0;
		err = 0;
	}
	spin_unlock(&open_lock);
	return err;
}

static inline void calc_zcopy_hb_parameters(struct shared_hash_table * ht)
{

	u32 max_zkb_count_per_queue = ht->zkb_count / ht->hash_count;
	u32 max_size_per_queue = max_zkb_count_per_queue * sizeof(u64 *);

	//we can calculate this better, find minima remainder which after divide BUCKET_SIZE
	ht->bucket_count_per_queue = max_size_per_queue / BUCKET_SIZE;
	if(ht->bucket_count_per_queue > H_MAX_POOL_BUCKET)
		ht->bucket_count_per_queue = H_MAX_POOL_BUCKET;

	if(ht->bucket_count_per_queue == 0)
	{
		ht->bucket_count_per_queue = 1;
		ht->zkb_bucket_order =  get_order(max_size_per_queue);
		ht->zkb_bucket_size = PAGE_SIZE << --ht->zkb_bucket_order;
	}
	else
	{
		ht->zkb_bucket_order = get_order(BUCKET_SIZE);
		ht->zkb_bucket_size = BUCKET_SIZE;
	}

	ht->zkb_count_per_bucket = ht->zkb_bucket_size / sizeof(u64 *);
	ht->zkb_count_per_queue = ht->zkb_count_per_bucket * ht->bucket_count_per_queue;
}
static int init_data_struct_page(struct shared_hash_table ** ht)
{
	int ret = 0;
	
	*ht = (struct shared_hash_table *)get_zeroed_page(GFP_KERNEL);

	if(*ht == NULL)
	{
		ErrorPrintf("get hash_table page error\n");
		ret = -1;
	}
	(*ht)->hash_table_size += PAGE_SIZE;
	return ret;
}
static void free_rw_htable_mem(struct shared_hash_table * ht)
{
	u32 i, j;

	if(ht == NULL)
		return;

	for(i = 0; i < ht->hash_count; ++i)
	{
		for(j = 0; j < ht->bucket_count_per_queue; ++j)
			if(ht->head[i].zkb_bucket_ptr[j])
				free_pages((unsigned long)ht->head[i].zkb_bucket_ptr[j], ht->zkb_bucket_order);
	}
	free_page((unsigned long)ht);
}
static void init_spinlock(spinlock_t * lock, u32 len)
{
	int i = 0;
	memset(lock, '\0', sizeof(spinlock_t) * len);
	for(i = 0; i < len; ++i)
		spin_lock_init(&lock[i]);
}
static int init_rw_hash_bucket(struct zcopy_info * zi, struct shared_hash_table ** ht, int read)
{
	int i = 0, j = 0;

	struct zcopy_buckets * zb = NULL;

	if(rw_disabled(zi, read))
		return 0;

	if((zi->thread_num <= 0) || (zi->thread_num > MAX_QUEUES))
	{
		ErrorPrintf("queue count %d error!\n", zi->thread_num);
		return -1;
	}

	if(init_data_struct_page(ht))
		goto init_data_page_err;

	(*ht)->hash_count = zi->thread_num;

	if(read)
	{
		(*ht)->zkb_count = zcopy_rmem.zkb_count;
		(*ht)->start_index = zcopy_rmem.start_index;
		init_spinlock(rlock, zi->thread_num);
	}
	else
	{
		(*ht)->zkb_count = zcopy_wmem.zkb_count;
		(*ht)->start_index = zcopy_wmem.start_index;
	}

	calc_zcopy_hb_parameters(*ht);

	DebugPrintf("%s: skb_count %llu, start_index %u, hash_count %u, skb_count_per_bucket %u, bucket_count_per_queue %u, skb_bucket_size %u, skb_bucket_order %u, free slot count %u.\n", 
			(read ? "read" : "write"), (*ht)->zkb_count, (*ht)->start_index, (*ht)->hash_count, (*ht)->zkb_count_per_bucket, \
			(*ht)->bucket_count_per_queue, (*ht)->zkb_bucket_size, (*ht)->zkb_bucket_order, free_slot_count());
	
	zb = (*ht)->head;
	for(i = 0; i < (*ht)->hash_count; ++i)
	{
		zb[i].zkb_in = zb[i].zkb_out = 0;
		for(j = 0; j < (*ht)->bucket_count_per_queue; ++j)
		{
			zb[i].zkb_bucket_ptr[j] = (void*) __get_free_pages(GFP_KERNEL, (*ht)->zkb_bucket_order);
			if(zb[i].zkb_bucket_ptr[j] == NULL)
				goto alloc_bucket_ptr_err;
			memset(zb[i].zkb_bucket_ptr[j], '\0', (*ht)->zkb_bucket_size);
#ifdef DEBUG
			if(j == 0)
				((u32 *)zb[i].zkb_bucket_ptr[j])[0] = 0x19841022;
#endif
			(*ht)->hash_table_size += (*ht)->zkb_bucket_size;
		}
	}
	if(read)
		zi->rx_ht_size = (*ht)->hash_table_size;
	else
		zi->wx_ht_size = (*ht)->hash_table_size;

	return 0;
alloc_bucket_ptr_err:
	free_rw_htable_mem(*ht);
init_data_page_err:
	return -1;
}

static void free_rw_zcopy_rmem(void)
{
	free_rw_htable_mem(rhash_table);
	rhash_table = NULL;
	free_rw_htable_mem(whash_table);
	whash_table = NULL;
	free_zkb_index_ptr();
	//here has a trick things i hava changed it. original free rmem first
	free_rw_remap_mem(&zcopy_wmem);
	free_rw_remap_mem(&zcopy_rmem);
	DebugPrintf("free all of memory !\n");
	DebugPrintf("\n\n");
}
#ifdef DEBUG
static void test_init_skb(void)
{
	u64 i = 1;

	DebugPrintf("start test read skb %llu, start_index %u!\n", zcopy_rmem.zkb_count, zcopy_rmem.start_index);
	DebugPrintf("start test write skb %llu, start_index %u!\n", zcopy_wmem.zkb_count, zcopy_wmem.start_index);

	for(i = 1; i < zcopy_rmem.zkb_count; ++i)
	{
		struct sk_zcopy * zkb;
		zkb = get_zkb_by_index(i + zcopy_rmem.start_index);
		if((zkb->magic != FROMKERNEL) || (zkb->index != (i + zcopy_rmem.start_index)))
		{
			DebugPrintf("read %llu: skb->index %u magic %x\n", i, zkb->index, zkb->magic);
			break;
		}
	}
	for(i = 1; i < zcopy_wmem.zkb_count; ++i)
	{
		struct sk_zcopy * zkb;
		zkb = get_zkb_by_index(i + zcopy_wmem.start_index);
		if((zkb->magic != FROMUSER) || (zkb->index != (i + zcopy_wmem.start_index)))
		{
			DebugPrintf("write %llu: skb->index %u magic %x\n", i, zkb->index, zkb->magic);
			break;
		}
	}
}
#else
static void test_init_zkb(void){}
#endif

static int zcopy_reclaim_task(void * data)
{
	DebugPrintf("reclaim thread %d start run !\n", task_pid_nr(current));
	while(!kthread_should_stop())
	{
		int count = skb_queue_len(&usage_head);
		while((count-- > 0) && zcopy_rmem.started)
		{
			reclaim_usaged_zkb(1);
			cond_resched();
		}
		msleep(100);
	}
	return 0;
}
static inline void workthread_should_sleep(struct thread_queue_info * tqueue_info)
{
	int i = 0, need_sleep = 1;
	struct zcopy_buckets * zb = whash_table->head;

	for(i = tqueue_info->start_queue; i <= tqueue_info->end_queue; ++i)
	{
		u32 out, in;
		out = zb[i].zkb_out % whash_table->zkb_count_per_queue;
		in = zb[i].zkb_in % whash_table->zkb_count_per_queue;
		if(out != in)
		{
			need_sleep = 0;
			break;
		}
	}

	if(need_sleep && ((get_jiffies_64() - tqueue_info->last_jiffies) > msecs_to_jiffies(2000)))
	{
		tqueue_info->last_jiffies = get_jiffies_64();
		msleep(10);
	}
}
static inline int net_device_is_ready(struct net_device * dev)
{
	return netif_running(dev) && netif_carrier_ok(dev);
}
//just for test if it has good performance.
//also this will have a potential bug, it should test dev_base_lock lock.
static struct net_device * last_dev = NULL;
static int zcopy_xmit(struct zcopy_buckets * zb, u32 queue)
{
	u64 * ptr;
	u64 zkb_index = 0;
	struct net_device * dev = NULL;
	const struct net_device_ops * ops = NULL;
	struct netdev_queue *txq = NULL;
	struct sk_zcopy * zkb = NULL;
	int status, ret = 0;

	ptr = get_ptr_position(whash_table, queue, zb->zkb_out);
	zkb_index = *ptr;

	read_barrier_depends();

	if(zkb_index == 0)
	{
		DebugPrintf("queue %d, in %u, out %u, skb_index is %llu.\n", queue, zb->zkb_in, zb->zkb_out, *ptr);
		++zb->zkb_out;
		goto xmit_err;
	}

	zkb = get_zkb_by_index(zkb_index);
	if(zkb == NULL)
	{
		++zb->zkb_out;
		goto xmit_err;
	}

	if(last_dev && (zkb->nic_index == last_dev->ifindex))
	{
		dev = last_dev;
		dev_hold(dev);
	}
	else
	{
		dev = dev_get_by_index(&init_net, zkb->nic_index);
		last_dev = dev;
	}
	if(dev == NULL)
	{
		DebugPrintf("Nic index %u is not correct !\n", zkb->nic_index);
		++zb->zkb_out;
		zkb->usage = 0;
		goto xmit_err;
	}

	zb->stop_queue = !net_device_is_ready(dev);
	if(zb->stop_queue)
	{
		DebugPrintf("net device is not ready !\n");
		ret = -1;
		goto xmit_err;
	}

#ifdef DEBUG
	if(zkb->queue_index != queue)
	{
		DebugPrintf("queue %d != skb->queue_index %u.\n", queue, zkb->queue_index);
	}
#endif

	convert_and_init_sk_zcopy(zkb, dev);
	if(NET_IP_ALIGN)
		skb_reserve(convert_sk_buff(zkb), NET_IP_ALIGN);
	skb_put(convert_sk_buff(zkb), zkb->len);
	
	convert_sk_buff(zkb)->queue_mapping = zkb->index; //circle netcard ring, avoid just use one ring.
	txq = netdev_get_tx_queue(dev, skb_get_queue_mapping(convert_sk_buff(zkb)) % dev->real_num_tx_queues);
	ops = dev->netdev_ops;
	//free zkb in netcard driver is just set the usage to 0
	zkb->free_zkb = free_user_zkb;

	__netif_tx_lock_bh(txq);
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,3,5)
	zb->stop_queue = netif_xmit_frozen_or_stopped(txq);
#else
	zb->stop_queue = netif_tx_queue_stopped(txq) || netif_tx_queue_frozen(txq);
#endif
	if(zb->stop_queue)
		status = NETDEV_TX_BUSY;
	else
		status = ops->ndo_start_xmit(convert_sk_buff(zkb), dev);
	switch(status)
	{
		case NETDEV_TX_OK:
			txq_trans_update(txq);
			++zb->zkb_out;
			if(zkb_from_kernel(zkb))
				*ptr = 0;
			break;
		default:
			ret = -1;
			break;
	}
	__netif_tx_unlock_bh(txq);
xmit_err:
	if(dev)
		dev_put(dev);
	return ret;
}

static struct send_thread_info sti;
static int send_packets_fun(void * data)
{
	u32 i = 0; 
	struct zcopy_buckets * zb = NULL;
	struct thread_queue_info * tqueue_info = (struct thread_queue_info *)data;
	zb = whash_table->head;

	DebugPrintf("kernel thread %d start run !\n", task_pid_nr(current));
	DebugPrintf("start queue %u, end queue %u.\n", tqueue_info->start_queue, tqueue_info->end_queue);

	i = tqueue_info->start_queue;
	while(!kthread_should_stop())
	{
		u32 out = 0, in = 0;

		if(i > tqueue_info->end_queue)
		{
			i = tqueue_info->start_queue;
			cond_resched();
		}
		
		workthread_should_sleep(tqueue_info);

		out = zb[i].zkb_out % whash_table->zkb_count_per_queue;
		in = zb[i].zkb_in % whash_table->zkb_count_per_queue;
		if(out == in)
		{
			++i;
			continue;
		}

		if(zcopy_xmit(&zb[i], i))
		{
			reclaim_usaged_zkb(1);
			cond_resched();
		}
		++i;
	}
	return 0;
}
static void stop_send_thread_task(void)
{
	int i = 0;
	for(i = 0; i < zcopy_wmem.nics; ++i)
		if(sti.send_task[i])
			kthread_stop(sti.send_task[i]);
}
static int init_send_thread(void)
{
	int ret = -1;
	int piece = 0;
	int i = 0;

	//No sent NIC
	if(zcopy_wmem.nics == 0)
		return 0;

	memset(&sti, '\0', sizeof(struct send_thread_info));
	memset(&usage_head, '\0', sizeof(struct sk_buff_head));

	skb_queue_head_init(&usage_head);

	piece = whash_table->hash_count / zcopy_wmem.nics;
	if(whash_table->hash_count % zcopy_wmem.nics)
		++piece;

	for(i = 0; i < zcopy_wmem.nics; ++i)
	{
		sti.tqueue_info[i].dev = dev_get_by_index(&init_net, zcopy_wmem.nic[i]);
		if(sti.tqueue_info[i].dev == NULL)
		{
			ErrorPrintf("nic index %d did't found a net device.\n", zcopy_wmem.nic[i]);
			ErrorPrintf("workqueue thread exit !\n");
			goto err;
		}
		DebugPrintf("%s: real num tx queues %u !\n", sti.tqueue_info[i].dev->name, sti.tqueue_info[i].dev->real_num_tx_queues);

		sti.tqueue_info[i].start_queue = i * piece;
		sti.tqueue_info[i].end_queue = ((i + 1) * piece - 1);
		if(sti.tqueue_info[i].end_queue >= whash_table->hash_count)
			sti.tqueue_info[i].end_queue = whash_table->hash_count - 1;
	}
#ifdef DEBUG
	DebugPrintf("nics %d.\n", zcopy_wmem.nics);
	for(i = 0; i < zcopy_wmem.nics; ++i)
		DebugPrintf("nid %u: start queue %u, end queue %u.\n", sti.tqueue_info[i].dev->ifindex, \
				sti.tqueue_info[i].start_queue, sti.tqueue_info[i].end_queue);
#endif

	for(i = 0; i < zcopy_wmem.nics; ++i)
	{
		sti.send_task[i] = kthread_create(send_packets_fun, (void*)&sti.tqueue_info[i], "send_packet_%d", i);
		if(IS_ERR(sti.send_task))
		{
			DebugPrintf("create send thread failed!\n");
			sti.send_task[i] = NULL;
			goto err;
		}
	}

	sti.reclaim_task = kthread_create(zcopy_reclaim_task, NULL, "zcopy_reclaim_task");
	if(IS_ERR(sti.reclaim_task))
	{
		DebugPrintf("create reclaim thread failed!\n");
		sti.reclaim_task = NULL;
		goto err;
	}
	return 0;
err:
	stop_send_thread_task();
	return ret;
}
static void start_send_thread(void)
{
	int i;
	for(i = 0; i < zcopy_wmem.nics; ++i)
		wake_up_process(sti.send_task[i]);

	if(zcopy_wmem.nics)
		wake_up_process(sti.reclaim_task);
}
static void free_send_thread(void)
{
	int i;

	if(sti.reclaim_task)
		kthread_stop(sti.reclaim_task);

	stop_send_thread_task();

	for(i = 0; i < zcopy_wmem.nics; ++i)
		if(sti.tqueue_info[i].dev)
			dev_put(sti.tqueue_info[i].dev);
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,3,5))
static long zerocopy_rw_ioctl(struct file * filp, unsigned int cmd, unsigned long arg)
#else
static int zerocopy_rw_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg)
#endif
{
	int ret = 0;
	struct zcopy_info zi;
	switch (cmd) 
	{
		case ZCOPY_MAP_INIT:
			ret = copy_from_user(&zi, (void __user *)arg, sizeof(struct zcopy_info));
			if (ret)
			{
				ErrorPrintf("copy from user err %d\n", ret);
				break;
			}
			
			DebugPrintf("============= read ================\n");
			ret = init_rw_zcopy_mem(&zi, &zcopy_rmem, 1);
			if(ret)
				break;

			ret = init_rw_hash_bucket(&zi, &rhash_table, 1);
			if(ret)
				break;
			
			DebugPrintf("============= write ===============\n");
			ret = init_rw_zcopy_mem(&zi, &zcopy_wmem, 0);
			if(ret)
				break;

			ret = init_rw_hash_bucket(&zi, &whash_table, 0);
			if(ret)
				break;
			
			ret = init_send_thread();
			if(ret)
				break;

			ret = copy_to_user((void __user *)arg, &zi, sizeof(struct zcopy_info));
			if(ret)
				ErrorPrintf("copy to user err %d\n", ret);
			
			break;
		case ZCOPY_MAP_RX:
			map_type = MAP_RX_MEM;
			break;
		case ZCOPY_MAP_WX:
			map_type = MAP_WX_MEM;
			break;
		case ZCOPY_MAP_HT_RX:
			map_type = MAP_RXHT_MEM;
			break;
		case ZCOPY_MAP_HT_WX:
			map_type = MAP_WXHT_MEM;
			break;
		case ZCOPY_START_WORK:
			start_zero_copy();
			start_send_thread();
			test_init_skb();
			break;
		default:
			ErrorPrintf("unknown command %u.\n", cmd);
			ret = -1;
			break;
	}

	return ret;
}

static int mmap_rx_mem(struct vm_area_struct * vma, struct zcopy_rw_mem * mem)
{
	u32 i = 0;
	unsigned long virt;

	if(mem->total_mem == 0)
		return 0;

	if ((vma->vm_end - vma->vm_start) != mem->total_mem)
	{
		ErrorPrintf("vm remmap size %lu != remmap size %llu.\n", (vma->vm_end - vma->vm_start), mem->total_mem);
		goto remmap_err;
	}

	//nocache
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	virt = vma->vm_start;

	for (i = 0; i < mem->remap_count; i++)
	{
		u64 pfn = page_to_pfn(virt_to_page(mem->remap_table[i]));
		if (remap_pfn_range(vma, virt, pfn, mem->remap_bucket_size, vma->vm_page_prot))
		{
			ErrorPrintf("remap_pfn_range err: virt %lu, pfn, %llu\n", virt, pfn);
			goto remmap_err;
		}
		virt += mem->remap_bucket_size;
	}

	DebugPrintf("remap_pfn_rang page ok, size %llu. start virt address[%lx]\n", mem->total_mem, vma->vm_start);

	return 0;
remmap_err:
	return -1;

}
static int mmap_rwht_mem(struct vm_area_struct * vma, struct shared_hash_table * ht)
{
	u32 i = 0, j = 0;
	u64 pfn;
	struct zcopy_buckets * zb = NULL;
	unsigned long virt;

	if ((vma->vm_end - vma->vm_start) != ht->hash_table_size)
	{
		ErrorPrintf("vm remmap size %lu != phy remmap size %u.\n", (vma->vm_end - vma->vm_start), ht->hash_table_size);
		goto remmap_err;
	}
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	virt = vma->vm_start;

	zb = ht->head;

	pfn = page_to_pfn(virt_to_page(ht));
	if (remap_pfn_range(vma, virt, pfn, PAGE_SIZE, vma->vm_page_prot))
	{
		ErrorPrintf("remap_pfn_range first page err: virt %lu, pfn, %llu\n", virt, pfn);
		goto remmap_err;
	}

	virt += PAGE_SIZE;

	for(i = 0; i < ht->hash_count; ++i)
	{
		for(j = 0; j < ht->bucket_count_per_queue; ++j)
		{
			pfn = page_to_pfn(virt_to_page(zb[i].zkb_bucket_ptr[j]));
			if (remap_pfn_range(vma, virt, pfn, ht->zkb_bucket_size, vma->vm_page_prot))
			{
				ErrorPrintf("remap_pfn_range rxht err: virt %lu, pfn, %llu\n", virt, pfn);
				goto remmap_err;
			}
			virt += ht->zkb_bucket_size;
		}
	}
	return 0;
remmap_err:
	return -1;
}
static int zerocopy_rw_mmap(struct file * filp, struct vm_area_struct * vma)
{
	int ret = 0;
	switch (map_type)
	{
		case MAP_RX_MEM:
			ret = mmap_rx_mem(vma, &zcopy_rmem);
			break;
		case MAP_WX_MEM:
			ret = mmap_rx_mem(vma, &zcopy_wmem);
			break;
		case MAP_RXHT_MEM:
			ret = mmap_rwht_mem(vma, rhash_table);
			break;
		case MAP_WXHT_MEM:
			ret = mmap_rwht_mem(vma, whash_table);
			break;
		default:
			ErrorPrintf("map type %x error\n", map_type);
			ret = -1;
			break;
	}
	return ret;
}
static void reinitialize_netcard_queue(void)
{
	int i;
	struct net_device * dev = NULL;
	for(i = 0; i < zcopy_rmem.nics; ++i)
	{
		dev = dev_get_by_index(&init_net, zcopy_rmem.nic[i]);
		if(!dev)
			continue;

		rtnl_lock();
		dev_close(dev);
		dev_open(dev);
		rtnl_unlock();
		dev_put(dev);
		ssleep(2);
	}
}
static int zerocopy_rw_release(struct inode *inode, struct file *filp)
{
	stop_zero_copy();
	free_send_thread();
	reinitialize_netcard_queue();
	map_type = 0;
	free_rw_zcopy_rmem();
	--open_count;
	return 0;
}

static struct file_operations zerocopy_rw_fop =
{
	.owner = THIS_MODULE,
	.read = zerocopy_rw_read,
	.write = zerocopy_rw_write,
	.mmap = zerocopy_rw_mmap,
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,3,5))
	.unlocked_ioctl = zerocopy_rw_ioctl,
#else
	.ioctl = zerocopy_rw_ioctl,
#endif
	.open = zerocopy_rw_open,
        .release = zerocopy_rw_release,
};

static ssize_t proto_show(char * buf, u32 proto)
{
	u32 show = 0; 
	if(protocol_flag & proto) 
		show = 1; 
	return sprintf(buf, "%u\n", show); 
}

static ssize_t proto_store(const char *buf, size_t count, u32 proto)
{
	int err;
	unsigned long flags;

	err = strict_strtoul(buf, 10, &flags);
	if(err || flags > UINT_MAX)
		return -EINVAL;
	if(flags > 1)
		return -EINVAL;

	if(flags == 0)
		protocol_flag &= ~proto;
	else
		protocol_flag |= proto;
	return count;
}

#define ZCOPY_ATTR_RO(_name) static struct kobj_attribute _name##_attr = __ATTR_RO(_name)
#define ZCOPY_ATTR(_name) static struct kobj_attribute _name##_attr = __ATTR(_name, 0644, _name##_show, _name##_store)
#define ZCOPY_SYSFS_FUNC(name, PROTO) \
static ssize_t name##_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) \
{ \
	return proto_show(buf, PROTO); \
} \
static ssize_t name##_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) \
{ \
	return proto_store(buf, count, PROTO); \
}
ZCOPY_SYSFS_FUNC(rarp, ZERO_RARP);
ZCOPY_ATTR(rarp);
ZCOPY_SYSFS_FUNC(arp, ZERO_ARP);
ZCOPY_ATTR(arp);
ZCOPY_SYSFS_FUNC(icmp, ZERO_ICMP);
ZCOPY_ATTR(icmp);
ZCOPY_SYSFS_FUNC(udp, ZERO_UDP);
ZCOPY_ATTR(udp);
ZCOPY_SYSFS_FUNC(tcp, ZERO_TCP);
ZCOPY_ATTR(tcp);

static ssize_t all_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	u32 show = 0;
	if(protocol_flag == ZERO_ALL)
		show = 1;
	return sprintf(buf, "%u\n", show);
}

static ssize_t all_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	int err;
	unsigned long flags;

	err = strict_strtoul(buf, 10, &flags);
	if(err || flags > UINT_MAX)
		return -EINVAL;
	if(flags > 1)
		return -EINVAL;

	if(flags == 0)
		protocol_flag = 0;
	else
		protocol_flag = ZERO_ALL;
	return count;
}
ZCOPY_ATTR(all);

static ssize_t queue_info_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	ssize_t len = 0;
	if(zcopy_rmem.started)
	{
		if(rhash_table)
		{
			len += sprintf(buf + len, "read  queue skb total %llu now %u.\n", zcopy_rmem.zkb_count, skb_queue_len(&zcopy_rmem.head));
			len += sprintf(buf + len, "read  queue skb count per queue %u.\n", rhash_table->zkb_count_per_queue);
		}
		if(whash_table)
		{

			len += sprintf(buf + len, "wating reclaim skb count %u.\n", skb_queue_len(&usage_head));
			// skb->index=0 for userspace skb count
			len += sprintf(buf + len, "write queue skb total %llu now %u.\n", zcopy_wmem.zkb_count, get_zkb_by_index(0)->usage);
			len += sprintf(buf + len, "write queue skb count per queue %u.\n", whash_table->zkb_count_per_queue);
		}
	}
	return len;
}
ZCOPY_ATTR_RO(queue_info);

static ssize_t queue_receive_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	ssize_t len = 0;
	int i = 0;
	struct zcopy_buckets * zb = NULL;
	if(zcopy_rmem.started && rhash_table)
	{
		zb = rhash_table->head;
		for(i = 0; i < rhash_table->hash_count; ++i)
		{
			len += sprintf(buf + len, "queue %2d: skb_in %8u -> skb_out %8u, drop %4u.\n", \
					i, zb[i].zkb_in % rhash_table->zkb_count_per_queue, zb[i].zkb_out % rhash_table->zkb_count_per_queue, zb[i].drop_count);
		}
	}
	return len;
}
ZCOPY_ATTR_RO(queue_receive);

static ssize_t queue_send_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	ssize_t len = 0;
	int i = 0;
	struct zcopy_buckets * zb = NULL;
	if(zcopy_rmem.started && whash_table)
	{
		zb = whash_table->head;
		for(i = 0; i < whash_table->hash_count; ++i)
		{
			len += sprintf(buf + len, "queue %2d: skb_in %8u -> skb_out %8u, drop %4u.\n", \
					i, zb[i].zkb_in % whash_table->zkb_count_per_queue, zb[i].zkb_out % whash_table->zkb_count_per_queue, zb[i].drop_count);
		}
	}
	return len;
}
ZCOPY_ATTR_RO(queue_send);

static struct attribute * zcopy_attrs[] = {
	&queue_info_attr.attr,
	&queue_receive_attr.attr,
	&queue_send_attr.attr,
	&arp_attr.attr,
	&rarp_attr.attr,
	&icmp_attr.attr,
	&tcp_attr.attr,
	&udp_attr.attr,
	&all_attr.attr,
	NULL,   /* need to NULL terminate the list of attributes */
};

static struct attribute_group zcopy_attr_group = {
	.attrs = zcopy_attrs,
};

static struct class * cdev_class = NULL;
static struct device * zcopy_device = NULL;
static struct kobject * zcopy_kobj = NULL;
static int zero_copy_rw_init(void)
{
	if(register_chrdev(ZEROCOPY_MAJOR, ZEROCOPY_NAME, &zerocopy_rw_fop))
	{
		ErrorPrintf("register char device [%s] failed !\n", ZEROCOPY_NAME);
		goto cdev_err;
	}

	cdev_class = class_create(THIS_MODULE, ZEROCOPY_NAME);
	if(IS_ERR(cdev_class))
	{
		ErrorPrintf("create class [%s] failed !\n", ZEROCOPY_NAME);
		goto create_class_err;
	}

	zcopy_device = device_create(cdev_class, NULL, MKDEV(ZEROCOPY_MAJOR, 0), NULL, ZEROCOPY_NAME);
	if(zcopy_device == NULL)
	{
		ErrorPrintf("make /dev/%s failed !\n", ZEROCOPY_NAME);
		goto create_cdev_err;
	}

	zcopy_kobj = kobject_create_and_add("net_zero_copy", NULL);
	if(zcopy_kobj == NULL)
	{
		ErrorPrintf("create net_zero_copy in sysfs failed !\n");
		goto sysfs_err;
	}

	if(sysfs_create_group(zcopy_kobj, &zcopy_attr_group))
	{
		ErrorPrintf("cannot create sysfs group for zcopy !\n");
		goto sysfs_group_err;
	}

	register_zero_copy_alloc_release_fun(alloc_zcopy_zkb, free_zcopy_zkb);
	register_zero_copy_deliver_fun(deliver_zcopy_zkb);

	return 0;

sysfs_group_err:
	kobject_put(zcopy_kobj);
sysfs_err:
	device_destroy(cdev_class, MKDEV(ZEROCOPY_MAJOR, 0));
create_cdev_err:
	class_destroy(cdev_class);
create_class_err:
	unregister_chrdev(ZEROCOPY_MAJOR, ZEROCOPY_NAME);
cdev_err:
	return -1;
}

static void zero_copy_rw_exit(void)
{
	unregister_zero_copy_alloc_release_fun();
	unregister_zero_copy_deliver_fun();
	sysfs_remove_group(zcopy_kobj, &zcopy_attr_group);
	kobject_put(zcopy_kobj);
	device_destroy(cdev_class, MKDEV(ZEROCOPY_MAJOR, 0));
	class_destroy(cdev_class);
	unregister_chrdev(ZEROCOPY_MAJOR, ZEROCOPY_NAME);
}

module_init(zero_copy_rw_init);
module_exit(zero_copy_rw_exit);
MODULE_LICENSE("GPL");
