#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "icmp.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweeping thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// lookup the IP->mac mapping
//
// traverse the table to find whether there is an entry with the same IP
// and mac address with the given arguments
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	  //fprintf(stderr, "TODO: lookup ip address in arp cache.\n");
    //postulates that ip4 is of host order
    pthread_mutex_lock(&arpcache.lock);
    int found = 0;
    for(int i = 0; i < MAX_ARP_SIZE; i++){
        if(arpcache.entries[i].valid){
            if(ip4 == arpcache.entries[i].ip4){
                found = 1;
                memcpy(mac, arpcache.entries[i].mac, ETH_ALEN);
                break;
            }
        }
    }
    pthread_mutex_unlock(&arpcache.lock);
    return found;
}

// append the packet to arpcache
//
// Lookup in the list which stores pending packets, if there is already an
// entry with the same IP address and iface (which means the corresponding arp
// request has been sent out), just append this packet at the tail of that entry
// (the entry may contain more than one packet); otherwise, malloc a new entry
// with the given IP address and iface, append the packet, and send arp request.
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	  //fprintf(stderr, "TODO: append the ip address if lookup failed, and send arp request if necessary.\n");
    //the strategy is: only send arp request explicitly when the whole request list is established. when a new member appended to the req list, do nothing even if the whole list gonna be aborted soon.
    pthread_mutex_lock(&arpcache.lock);
    struct cached_pkt *cp = (struct cached_pkt *)malloc(sizeof(struct cached_pkt));
    cp->packet = (char *)malloc(len);
    memcpy(cp->packet, packet, len);
    cp->len = len;
    
    struct arp_req *entry_ar;
    int found_list = 0;
    list_for_each_entry(entry_ar, &arpcache.req_list, list){
        if(entry_ar->ip4 == ip4 && entry_ar->iface == iface){
            found_list = 1;
            list_add_tail(&cp->list, &entry_ar->cached_packets);
            break;
        }
    }
    
    if(!found_list){
        struct arp_req *ar = (struct arp_req *)malloc(sizeof(struct arp_req));
        ar->iface = iface;
        ar->ip4 = ip4;
        ar->retries = 1;
        init_list_head(&ar->cached_packets);
        list_add_tail(&cp->list, &ar->cached_packets);
        list_add_tail(&ar->list, &arpcache.req_list);
        ar->sent = time(NULL);
        arp_send_request(iface, ip4);
    }
    pthread_mutex_unlock(&arpcache.lock);
}

// insert the IP->mac mapping into arpcache, if there are pending packets
// waiting for this mapping, fill the ethernet header for each of them, and send
// them out
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	  //fprintf(stderr, "TODO: insert ip->mac entry, and send all the pending packets.\n");
    //asserts that this mapping does not exist in cache now
    //postulates that ip4 is of host order
    pthread_mutex_lock(&arpcache.lock);
    int i;
    int pos = MAX_ARP_SIZE;
    for(i = 0; i < MAX_ARP_SIZE; i++){
        if(!arpcache.entries[i].valid){
            pos = i;
            break;
        }
    }
    
    for(i = 0; i < MAX_ARP_SIZE; i++){
        if(arpcache.entries[i].valid){
            if(arpcache.entries[i].ip4 == ip4){
                pos = i;
                break;
            }
        }
    }
    
    if(pos == MAX_ARP_SIZE){
        srand(time(NULL));
        pos = rand() % MAX_ARP_SIZE;
    }
    
    arpcache.entries[pos].ip4 = ip4;
    memcpy(&arpcache.entries[pos].mac, mac, ETH_ALEN);
    arpcache.entries[pos].added = time(NULL);
    arpcache.entries[pos].valid = 1;
    
    struct arp_req *entry_ar, *q;
    list_for_each_entry_safe(entry_ar, q, &arpcache.req_list, list){
        if(entry_ar->ip4 == ip4){
            struct cached_pkt *entry_cp, *p;
            list_for_each_entry_safe(entry_cp, p, &entry_ar->cached_packets, list){
                struct ether_header *eh = (struct ether_header *)entry_cp->packet;
                memcpy(eh->ether_dhost, mac, ETH_ALEN);
                iface_send_packet(entry_ar->iface, entry_cp->packet, entry_cp->len);
                list_delete_entry(&entry_cp->list);
                //log(DEBUG, "can you free to here1?\n");
                //free(entry_cp->packet);
                //log(DEBUG, "can you free to here2?\n");
                free(entry_cp);
            }
            list_delete_entry(&entry_ar->list);
            //log(DEBUG, "can you free to here3?\n");
            free(entry_ar);
        }
    }
    pthread_mutex_unlock(&arpcache.lock);
}

// sweep arpcache periodically
//
// For the IP->mac entry, if the entry has been in the table for more than 15
// seconds, remove it from the table.
// For the pending packets, if the arp request is sent out 1 second ago, while 
// the reply has not been received, retransmit the arp request. If the arp
// request has been sent 5 times without receiving arp reply, for each
// pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these
// packets.
void *arpcache_sweep(void *arg) 
{
	  while (1) {
		    sleep(1);
		    //fprintf(stderr, "TODO: sweep arpcache periodically: remove old entries, resend arp requests .\n");
        struct list_head icmp_list;
        init_list_head(&icmp_list);
        pthread_mutex_lock(&arpcache.lock);
        time_t now = time(NULL);
        
        for(int i = 0; i < MAX_ARP_SIZE; i++){
            if(now - arpcache.entries[i].added >= ARP_ENTRY_TIMEOUT){
                arpcache.entries[i].valid = 0;
            }
        }
        
        struct arp_req *entry_ar, *q;
        list_for_each_entry_safe(entry_ar, q, &arpcache.req_list, list){
            if(now - entry_ar->sent >= 1){
                entry_ar->retries += 1;
                entry_ar->sent = now;
                arp_send_request(entry_ar->iface, entry_ar->ip4);
                //log(DEBUG, "target %d has retried %d times.\n", entry_ar->ip4, entry_ar->retries);
            }
            if(entry_ar->retries > ARP_REQUEST_MAX_RETRIES){
                //todo: send icmp packets
                //q: where to assemble ip header?
                //remember to free memories
                list_delete_entry(&entry_ar->list);
                list_add_tail(&entry_ar->list, &icmp_list);
            }
        }
        pthread_mutex_unlock(&arpcache.lock);
        
        list_for_each_entry_safe(entry_ar, q, &icmp_list, list){
            struct cached_pkt *entry_cp, *p;
            list_for_each_entry_safe(entry_cp, p, &entry_ar->cached_packets, list){
                icmp_send_packet(entry_cp->packet, entry_cp->len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
                list_delete_entry(&entry_cp->list);
                free(entry_cp->packet);
                free(entry_cp);
            }
            list_delete_entry(&entry_ar->list);
            free(entry_ar);
        }
	  }
}
