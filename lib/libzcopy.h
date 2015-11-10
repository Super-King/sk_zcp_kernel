#ifndef _LIBZCOPY_H_
#define _LIBZCOPY_H_

#ifdef __cplusplus
extern "C"
{
#endif
#include <pthread.h>
#include "zcopy.h"
#include "zcpag.h"


struct sk_zcopy_head {
	struct sk_zcopy  *next;
	struct sk_zcopy  *prev;

	__u32            qlen;
	pthread_mutex_t  lock;
};
struct map_addr_info
{
	__u64 map_size;
	__u64 ht_map_size;
	int map_flag;
	int ht_map_flag;
	void * map_addr;
	void * hash_addr;
};
struct zcopy_hash_table 
{
	struct shared_hash_table * ht;
	struct zcopy_buckets * zb;
	struct sk_zcopy ** zkb;
	struct sk_zcopy_head head;
	void * queue_ptr[MAX_QUEUES];
};

static inline void __zcopy_zkb_queue_head_init(struct sk_zcopy_head *list)
{
	list->prev = list->next = (struct sk_zcopy *)list;
	list->qlen = 0;
}

static inline void zcopy_zkb_queue_head_init(struct sk_zcopy_head * list)
{
	pthread_mutex_init(&list->lock, NULL);
	__zcopy_zkb_queue_head_init(list);
}
static inline struct sk_zcopy * zcopy_zkb_peek(struct sk_zcopy_head *list_)
{
	struct sk_zcopy *list = ((struct sk_zcopy *)list_)->next;
	if(list == (struct sk_zcopy *)list_)
		list = NULL;
	return list;
}
static inline void __zcopy_zkb_unlink(struct sk_zcopy *zkb, struct sk_zcopy_head *list)
{
	struct sk_zcopy *next, *prev;

	list->qlen--;
	next       = zkb->next;
	prev       = zkb->prev;
	zkb->next  = zkb->prev = NULL;
	next->prev = prev;
	prev->next = next;
}
static inline struct sk_zcopy *__zcopy_zkb_dequeue(struct sk_zcopy_head *list)
{
	struct sk_zcopy *zkb = zcopy_zkb_peek(list);
	if (zkb)
		__zcopy_zkb_unlink(zkb, list);
	return zkb;
}

static inline struct sk_zcopy * zcopy_zkb_dequeue(struct sk_zcopy_head *list)
{
	struct sk_zcopy * zkb;
	pthread_mutex_lock(&list->lock);
	zkb = __zcopy_zkb_dequeue(list);
	pthread_mutex_unlock(&list->lock);
	return zkb;
}

static inline void __zcopy_zkb_insert(struct sk_zcopy *newzk,
		struct sk_zcopy *prev, struct sk_zcopy *next, struct sk_zcopy_head *list)
{
	newzk->next = next;
	newzk->prev = prev;
	next->prev  = prev->next = newzk;
	list->qlen++;
}
static inline void __zcopy_zkb_queue_before(struct sk_zcopy_head *list,
		struct sk_zcopy *next, struct sk_zcopy *newzk)
{
	__zcopy_zkb_insert(newzk, next->prev, next, list);
}
static inline void __zcopy_zkb_queue_tail(struct sk_zcopy_head *list, struct sk_zcopy *newzk)
{
	__zcopy_zkb_queue_before(list, (struct sk_zcopy *)list, newzk);
}
static inline void zcopy_zkb_queue_tail(struct sk_zcopy_head *list, struct sk_zcopy *newzk)
{
	pthread_mutex_lock(&list->lock);
	__zcopy_zkb_queue_tail(list, newzk);
	pthread_mutex_unlock(&list->lock);
}
static inline __u32 zcopy_zkb_queue_len(const struct sk_zcopy_head *list_)
{
	return list_->qlen;
}
#ifdef __cplusplus
}
#endif

#endif
