#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"
#include "rtable.h"

#include "ip.h"

#include "list.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

extern ustack_t *instance;

pthread_mutex_t mospf_lock;
//a much more gorgeous implementation is to set a trigger: condition variable. in send_mospf_lsu_thread we do the send action itself after 
//pthread_cond_timedwait(30, cond). the wait process can be interrupted when cond is satisfied. so, we can trigger the cond when nbr list is modified to
// send lsu immediately.

void mospf_init()
{
	pthread_mutex_init(&mospf_lock, NULL);

	instance->area_id = 0;
	// get the ip address of the first interface
	iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
	instance->router_id = iface->ip;
	instance->sequence_num = 0;
	instance->lsuint = MOSPF_DEFAULT_LSUINT;

	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		iface->helloint = MOSPF_DEFAULT_HELLOINT;
		init_list_head(&iface->nbr_list);
	}

	init_mospf_db();
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);
void *checking_database_thread(void *param);

void mospf_run()
{
	pthread_t hello, lsu, nbr, db;
	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
	pthread_create(&db, NULL, checking_database_thread, NULL);
}

void *sending_mospf_hello_thread(void *param)
{
	  //fprintf(stdout, "TODO: send mOSPF Hello message periodically.\n");
    while(1){
        sleep(MOSPF_DEFAULT_HELLOINT);
        
        iface_info_t *entry;
        list_for_each_entry(entry, &instance->iface_list, list){
            //assemble hello packet: ether header, ip header, mospf header, mospf hello
            int len = sizeof(struct ether_header) + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE;
            char *message = (char *)malloc(len);
            
            struct ether_header *eh = (struct ether_header *)message;
            memcpy(eh->ether_shost, entry->mac, ETH_ALEN);
            eh->ether_dhost[0] = 0x01; eh->ether_dhost[1] = 0x00; eh->ether_dhost[2] = 0x5e;
            eh->ether_dhost[3] = 0x00; eh->ether_dhost[4] = 0x00; eh->ether_dhost[5] = 0x05;
            eh->ether_type = htons(0x0800);
            
            struct iphdr *ih = packet_to_ip_hdr(message);
            ip_init_hdr(ih, entry->ip, MOSPF_ALLSPFRouters, IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, IPPROTO_MOSPF);
            
            struct mospf_hdr *mh = (struct mospf_hdr *)(message + sizeof(struct ether_header) + IP_BASE_HDR_SIZE);
            mospf_init_hdr(mh, MOSPF_TYPE_HELLO, MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, instance->router_id, instance->area_id);
            
            struct mospf_hello *mhello = (struct mospf_hello *)(message + sizeof(struct ether_header) + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE);
            mospf_init_hello(mhello, entry->mask);
            
            mh->checksum = mospf_checksum(mh);
            
            //send hello packet
            iface_send_packet(entry, message, len);
        }
    }
}

void *checking_nbr_thread(void *param)
{
	  //fprintf(stdout, "TODO: neighbor list timeout operation.\n");
    //assume that when the neighbour is inserted into queue or updated, it's alive will be set to 0. this thread will add 1 to alive each time.
    while(1){
        sleep(1);
        pthread_mutex_lock(&mospf_lock);
        
        //age nbr_lists and check if any nbr is aged.
        int modified = 0;
        iface_info_t *entry_iface;
        list_for_each_entry(entry_iface, &instance->iface_list, list){
            mospf_nbr_t *entry_mnbr, *q;
            list_for_each_entry_safe(entry_mnbr, q, &entry_iface->nbr_list, list){
                entry_mnbr->alive += 1;
                if(entry_mnbr->alive >= 3*MOSPF_DEFAULT_HELLOINT){
                    modified = 1;
                    list_delete_entry(&entry_mnbr->list);
                    log(DEBUG, "sweep nbr\n");
                    free(entry_mnbr);
                    entry_iface->num_nbr -= 1;
                }
            }
        }
        if(modified){
            broadcast_mospf_lsu_prep(1);
            //log(DEBUG, "regen_rtable when chk nbrs\n");
            regenerate_rtable();
            //log(DEBUG, "regen succeeded when chk nbrs\n");
        }
        pthread_mutex_unlock(&mospf_lock);
    }
}

void *checking_database_thread(void *param)
{
    //fprintf(stdout, "TODO: link state database timeout operation.\n");
    while(1){
        sleep(1);
        pthread_mutex_lock(&mospf_lock);
        //age db
        mospf_db_entry_t *entry_mdbe, *q;
        int modified = 0;
        list_for_each_entry_safe(entry_mdbe, q, &mospf_db, list){
            entry_mdbe->alive += 1;
            if(entry_mdbe->alive >= MOSPF_DATABASE_TIMEOUT){
                modified = 1;
                list_delete_entry(&entry_mdbe->list);
                log(DEBUG, "sweep db\n");
                free(entry_mdbe->array);
                free(entry_mdbe);
            }
        }
        
        if(modified){
            //regenerate rtable
            log(DEBUG, "regen_rtable when chk db\n");
            regenerate_rtable();
            log(DEBUG, "regen succeeded when chk db\n");
        }
        pthread_mutex_unlock(&mospf_lock);
    }
}

void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
	  //fprintf(stdout, "TODO: handle mOSPF Hello message.\n");
    pthread_mutex_lock(&mospf_lock);
    
    struct iphdr *ih = packet_to_ip_hdr(packet);
    struct mospf_hdr *mhdr_hello = (struct mospf_hdr *)(packet + sizeof(struct ether_header) + IP_BASE_HDR_SIZE);
    struct mospf_hello *mhello = (struct mospf_hello *)((char *)mhdr_hello + MOSPF_HDR_SIZE);
    
    int nbr_insert = 1;
    mospf_nbr_t *entry_mnbr;
    list_for_each_entry(entry_mnbr, &iface->nbr_list, list){
        if(ntohl(mhdr_hello->rid) == entry_mnbr->nbr_id){
            nbr_insert = 0;
            entry_mnbr->nbr_ip = ntohl(ih->saddr);
            entry_mnbr->nbr_mask = ntohl(mhello->mask);
            entry_mnbr->alive = 0;
            break;
        }
    }
    
    if(nbr_insert){
        entry_mnbr = (mospf_nbr_t *)malloc(sizeof(mospf_nbr_t));
        entry_mnbr->nbr_id = ntohl(mhdr_hello->rid);
        entry_mnbr->nbr_ip = ntohl(ih->saddr);
        entry_mnbr->nbr_mask = ntohl(mhello->mask);
        entry_mnbr->alive = 0;
        
        list_add_tail(&entry_mnbr->list, &iface->nbr_list);
        iface->num_nbr += 1;
    }
    
    if(nbr_insert){
        broadcast_mospf_lsu_prep(1);
        //log(DEBUG, "regen_rtable when handle hello\n");
        regenerate_rtable();
        //log(DEBUG, "regen succeeded when handle hello\n");
    }
    pthread_mutex_unlock(&mospf_lock);
}

void *sending_mospf_lsu_thread(void *param)
{
	  //fprintf(stdout, "TODO: send mOSPF LSU message periodically.\n");
    while(1){
        sleep(MOSPF_DEFAULT_LSUINT);
        pthread_mutex_lock(&mospf_lock);
        broadcast_mospf_lsu_prep(0);
        pthread_mutex_unlock(&mospf_lock);
    }
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
	  //fprintf(stdout, "TODO: handle mOSPF LSU message.\n");
    struct iphdr *ih = packet_to_ip_hdr(packet);
    char *msg_lsu = IP_DATA(ih);
    struct mospf_hdr *mh = (struct mospf_hdr *)msg_lsu;
    if(ntohl(mh->rid) == instance->router_id) return;
    pthread_mutex_lock(&mospf_lock);
    
    update_db(msg_lsu);
    
    //regenerate rtable
    //log(DEBUG, "regen_rtable when handle lsu\n");
    regenerate_rtable();
    //log(DEBUG, "regen succeeded when handle lsu\n");
    
    struct mospf_hdr *mhdr = (struct mospf_hdr *)msg_lsu;
    if(ntohl(mhdr->rid) == instance->router_id) { pthread_mutex_unlock(&mospf_lock); return; }
    struct mospf_lsu *mlsu = (struct mospf_lsu *)(msg_lsu + MOSPF_HDR_SIZE);
    mlsu->ttl -= 1;
    mhdr->checksum = mospf_checksum(mhdr);
    if(mlsu->ttl > 0){
        broadcast_mospf_lsu(iface, ih, msg_lsu, len - sizeof(struct ether_header) - IP_BASE_HDR_SIZE);
    }
    
    
    pthread_mutex_unlock(&mospf_lock);
}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));

	if (mospf->version != MOSPF_VERSION) {
		log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
		return ;
	}
	if (mospf->checksum != mospf_checksum(mospf)) {
		log(ERROR, "received mospf packet with incorrect checksum");
		return ;
	}
	if (ntohl(mospf->aid) != instance->area_id) {
		log(ERROR, "received mospf packet with incorrect area id");
		return ;
	}

	switch (mospf->type) {
		case MOSPF_TYPE_HELLO:
			handle_mospf_hello(iface, packet, len);
			break;
		case MOSPF_TYPE_LSU:
			handle_mospf_lsu(iface, packet, len);
			break;
		default:
			log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
			break;
	}
}
