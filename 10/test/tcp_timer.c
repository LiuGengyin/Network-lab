#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

static struct list_head timer_list;
pthread_mutex_t timer_lock;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	  //fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
    pthread_mutex_lock(&timer_lock);
    
    struct tcp_timer *entry, *q;
    list_for_each_entry_safe(entry, q, &timer_list, list){
        if(entry->enable){
            if(entry->type == 0){
                entry->timeout += TCP_TIMER_SCAN_INTERVAL;
                if(entry->timeout >= TCP_TIMEWAIT_TIMEOUT){
                    list_delete_entry(&entry->list);
                    struct tcp_sock *tsk = timewait_to_tcp_sock(entry);
                    tcp_set_state(tsk, TCP_CLOSED);
                    tcp_unhash(tsk);
                    tcp_bind_unhash(tsk);
                }
            }
            /*else{
                
            }*/
        }
    }
    
    pthread_mutex_unlock(&timer_lock);
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	  //fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
    tsk->timewait.type = 0;
    tsk->timewait.enable = 1;
    tsk->timewait.timeout = 0;
    pthread_mutex_lock(&timer_lock);
    list_add_tail(&tsk->timewait.list, &timer_list);
    pthread_mutex_unlock(&timer_lock);
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
  pthread_mutex_init(&timer_lock, NULL);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}
