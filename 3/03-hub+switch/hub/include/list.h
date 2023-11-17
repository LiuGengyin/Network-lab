#ifndef __LIST_H__
#define __LIST_H__

#include <stddef.h>

struct list_head {
	struct list_head *next, *prev;
};

#define list_empty(list) ((list)->next == (list))

#define list_entry(ptr, type, member) \
	(type *)((char *)ptr - offsetof(type, member))

/*the arg head is a ptr pointing to the head of the list you want to traverse; the arg member is the name of a member in listnode, should be the name of list_head*/
#define list_for_each_entry(pos, head, member) \
	for (pos = list_entry((head)->next, typeof(*pos), member); \
			&pos->member != (head); \
			pos = list_entry(pos->member.next, typeof(*pos), member)) 

/*when you want to del or add some nodes when traversing, use this*/
#define list_for_each_entry_safe(pos, q, head, member) \
	for (pos = list_entry((head)->next, typeof(*pos), member), \
			q = list_entry(pos->member.next, typeof(*pos), member); \
			&pos->member != (head); \
			pos = q, q = list_entry(pos->member.next, typeof(*q), member))

static inline void init_list_head(struct list_head *list)
{
	list->next = list->prev = list;
}

static inline void list_insert(struct list_head *new,
		struct list_head *prev,
		struct list_head *next)
{
	next->prev = new;
	prev->next = new;
	new->next = next;
	new->prev = prev;
}

static inline void list_delete_entry(struct list_head *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	list_insert(new, head->prev, head);
}

#endif
