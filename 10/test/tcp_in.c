#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"
#include "plain_buf.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>
// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)

int total;
int seq_alr;

static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u16 old_snd_wnd = tsk->snd_wnd;
	tsk->snd_wnd = cb->rwnd;
	if (old_snd_wnd == 0)
		wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		log(DEBUG, "received packet with invalid seq, drop it.");
   
    if(!less_than_32b(cb->seq, rcv_end)) log(DEBUG, "seq too big");
    if(!less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) log(DEBUG, "seq too small");
		return 0;
	}
}

// Process the incoming packet according to TCP state machine. 
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	  //fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
    if(!tsk){ //target socket doen not exist in established table or listen table. which means, we are not ready to deal with this port.
              //so, omit this tcp packet and notify peer by send rst.
              //given that peer has sent this packet, it should have the relative socket in its tables. so when peer receives the rst packet,
              //in this process, tsk should't be NULL.
        log(DEBUG, "!tsk so rst");
        tcp_send_reset(cb);
        return;
    }
    
    if(cb->flags & TCP_RST){ //at any moment we can receive rst packet. but only established socket will recv rst, so tsk will be a child.
        tcp_set_state(tsk, TCP_CLOSED);
        //I keep the sock alive for now -- but logically it should be freed.
        //please check tsk->state when using this child sock: send and recv. if the state is CLOSED, unhash this sock from all tables then.
    }
    
    if(tsk->state == TCP_LISTEN){ //server: tsk is parent
        if(cb->flags == TCP_SYN){ //first handshake
            //allocate a child
            struct tcp_sock *child = alloc_tcp_sock();
            
            child->sk_sip = cb->daddr;
            child->sk_sport = cb->dport;
            child->sk_dip = cb->saddr;
            child->sk_dport = cb->sport;
            
            child->parent = tsk;
            child->mybuf = (struct buffer *)malloc(sizeof(struct buffer));
            init_buff(child->mybuf, 5000000);
            
            child->iss = tcp_new_iss();
            
            child->snd_nxt = child->iss;
            child->rcv_nxt = cb->seq_end;
            
            tcp_set_state(child, TCP_SYN_RECV);
            
            tcp_hash(child); //child -> established_table
            tcp_bind_hash(child);
            child->rcv_buf = alloc_ring_buffer(TCP_DEFAULT_WINDOW);
            list_add_tail(&child->list, &child->parent->listen_queue);
            
            tcp_send_control_packet(child, TCP_ACK | TCP_SYN);
        }
    }
    else if(tsk->state == TCP_SYN_RECV){ //server: tsk is child in parent's listen queue
        if((cb->flags == TCP_ACK) && is_tcp_seq_valid(tsk, cb)){ //get what we want: the third handshake
            tsk->snd_una = cb->ack;
            tcp_update_window_safe(tsk, cb);
            tsk->rcv_nxt = cb->seq_end;
            seq_alr = cb->seq_end;
            assert(tsk->parent);
            if(!tcp_sock_accept_queue_full(tsk->parent)){
                tcp_set_state(tsk, TCP_ESTABLISHED);
                tcp_sock_accept_enqueue(tsk);
                wake_up(tsk->parent->wait_accept);
            }
            else{
                log(DEBUG, "accept queue full so rst");
                tcp_send_reset(cb);
                list_delete_entry(&tsk->list);
                tcp_unhash(tsk);
                tcp_bind_unhash(tsk);
            }
        }
    }
    else if(tsk->state == TCP_ESTABLISHED){
        if(is_tcp_seq_valid(tsk, cb)){
            //log(DEBUG, "1");
            if(cb->flags & TCP_ACK){ //normal data packets. (maybe also FIN packet)
                tsk->snd_una = cb->ack;
                tcp_update_window_safe(tsk, cb);
            }
            if(cb->flags & TCP_FIN){
                tcp_set_state(tsk, TCP_CLOSE_WAIT);
                if(cb->pl_len == 0){
                    tsk->rcv_nxt = cb->seq_end;
                    tcp_send_control_packet(tsk, TCP_ACK);
                }
            }
            //normal data packet
            pthread_mutex_lock(&tsk->rcv_buf_lock);
            //printf("%d %d\n", cb->pl_len, buff_free(tsk->mybuf));
            if(cb->pl_len > buff_free(tsk->mybuf)){
                log(DEBUG, "drop pack for overflow");
                //wake_up(tsk->wait_recv);
                pthread_mutex_unlock(&tsk->rcv_buf_lock);
                return;
            }
            if(cb->pl_len == 0){ //third handshake
                //log(DEBUG, "rcv len 0");
                wake_up(tsk->wait_recv);
                pthread_mutex_unlock(&tsk->rcv_buf_lock);
                return;
            }
            write_buff(tsk->mybuf, cb->payload, cb->pl_len);
            total += cb->pl_len;
            //log(DEBUG, "%d", cb->pl_len);
            tsk->rcv_wnd = buff_free(tsk->mybuf);
            tsk->rcv_nxt = cb->seq_end;
            wake_up(tsk->wait_recv);
            tcp_send_control_packet(tsk, TCP_ACK);
            pthread_mutex_unlock(&tsk->rcv_buf_lock);
        }
    }
    else if(tsk->state == TCP_FIN_WAIT_1){
        if(is_tcp_seq_valid(tsk, cb)){
            if(cb->flags & TCP_ACK){
                tcp_set_state(tsk, TCP_FIN_WAIT_2);
                tsk->rcv_nxt = cb->seq_end;
                tsk->snd_una = cb->ack;
                tcp_update_window_safe(tsk, cb);
            }
        }
    }
    else if(tsk->state == TCP_FIN_WAIT_2){
        if(is_tcp_seq_valid(tsk, cb)){
            if(cb->flags & TCP_ACK){ //normal data packets. (maybe also FIN packet)
                tsk->snd_una = cb->ack;
                tcp_update_window_safe(tsk, cb);
            }
            if(cb->flags & TCP_FIN){
                tcp_set_state(tsk, TCP_TIME_WAIT);
                if(cb->pl_len == 0){
                    tsk->rcv_nxt = cb->seq_end;
                    tcp_send_control_packet(tsk, TCP_ACK);
                }
                tcp_set_timewait_timer(tsk);
            }
            { //normal data packet
                pthread_mutex_lock(&tsk->rcv_buf_lock);
                if(cb->pl_len > ring_buffer_free(tsk->rcv_buf)){
                    log(DEBUG, "drop pack for overflow");
                    //wake_up(tsk->wait_recv);
                    pthread_mutex_unlock(&tsk->rcv_buf_lock);
                    return;
                }
                if(cb->pl_len == 0){
                    wake_up(tsk->wait_recv);
                    pthread_mutex_unlock(&tsk->rcv_buf_lock);
                    return;
                }
                log(DEBUG, "tell me if recv any packet here");
                write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
                total += cb->pl_len;
                tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
                tsk->rcv_nxt = cb->seq_end;
                wake_up(tsk->wait_recv);
                tcp_send_control_packet(tsk, TCP_ACK);
                pthread_mutex_unlock(&tsk->rcv_buf_lock);
            }
        }
    }
    /*else if(tsk->state == TCP_TIME_WAIT){
        //actually we should do sth here, but no packet loss. 
    }*/
    else if(tsk->state == TCP_SYN_SENT){
        if(cb->flags == (TCP_ACK | TCP_SYN)){
            tsk->rcv_nxt = cb->seq_end;
            tsk->snd_una = cb->ack;
            tcp_update_window_safe(tsk, cb);
            
            tcp_set_state(tsk, TCP_ESTABLISHED);
            tcp_send_control_packet(tsk, TCP_ACK);
            wake_up(tsk->wait_connect);
        }
    }
    else if(tsk->state == TCP_LAST_ACK){
        if((cb->flags & TCP_ACK) && is_tcp_seq_valid(tsk, cb)){
            tsk->snd_una = cb->ack;
            tsk->rcv_nxt = cb->seq_end;
            tcp_set_state(tsk, TCP_CLOSED);
            tcp_unhash(tsk);
            tcp_bind_unhash(tsk);
        }
    }
}
