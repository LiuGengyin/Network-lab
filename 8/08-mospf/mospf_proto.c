#include "mospf_proto.h"
#include "mospf_database.h"
#include "mospf_daemon.h"
#include "mospf_nbr.h"
#include "ip.h"
#include "icmp.h"
#include "arp.h"
#include "rtable.h"
#include <arpa/inet.h>
#include <string.h>

extern ustack_t *instance;

void mospf_init_hdr(struct mospf_hdr *mospf, u8 type, u16 len, u32 rid, u32 aid)
{
	mospf->version = MOSPF_VERSION;
	mospf->type = type;
	mospf->len = htons(len);
	mospf->rid = htonl(rid);
	mospf->aid = htonl(aid);
	mospf->padding = 0;
}

void mospf_init_hello(struct mospf_hello *hello, u32 mask)
{
	hello->mask = htonl(mask);
	hello->helloint = htons(MOSPF_DEFAULT_HELLOINT);
	hello->padding = 0;
}

void mospf_init_lsu(struct mospf_lsu *lsu, u32 nadv)
{
	lsu->seq = htons(instance->sequence_num);
	lsu->unused = 0;
	lsu->ttl = MOSPF_MAX_LSU_TTL;
	lsu->nadv = htonl(nadv);
}

//this will be called in checking_nbr_thread, handle_mospf_hello(when triggered) and sending_mospf_lsu_thread(periodically).
void broadcast_mospf_lsu_prep(int local_db_need_upd){
    //assemble lsu message(without iphdr or etherhdr)
    int nbrs = 0;
    iface_info_t *entry_iface;
    list_for_each_entry(entry_iface, &instance->iface_list, list){
        if(entry_iface->num_nbr) nbrs += entry_iface->num_nbr;
        else nbrs += 1;
    }
    
    int len_lsu = MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nbrs * MOSPF_LSA_SIZE;
    char *msg_lsu = (char *)malloc(len_lsu);
    
    struct mospf_hdr *mh = (struct mospf_hdr *)msg_lsu; 
    mospf_init_hdr(mh, MOSPF_TYPE_LSU, len_lsu, instance->router_id, instance->area_id);
    
    struct mospf_lsu *mlsu = (struct mospf_lsu *)(msg_lsu + MOSPF_HDR_SIZE);
    mospf_init_lsu(mlsu, nbrs);
    instance->sequence_num += 1;
    
    struct mospf_lsa *mlsa = (struct mospf_lsa *)(msg_lsu + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE);
    int i = 0;
    list_for_each_entry(entry_iface, &instance->iface_list, list){
        if(entry_iface->num_nbr){
            mospf_nbr_t *entry_mnbr;
            list_for_each_entry(entry_mnbr, &entry_iface->nbr_list, list){
                mlsa[i].network = htonl(entry_mnbr->nbr_mask & entry_mnbr->nbr_ip);
                mlsa[i].mask = htonl(entry_mnbr->nbr_mask);
                mlsa[i].rid = htonl(entry_mnbr->nbr_id);
                i++;
            }
        }
        else{
            mlsa[i].network = htonl(entry_iface->ip & entry_iface->mask);
            mlsa[i].mask = htonl(entry_iface->mask);
            mlsa[i].rid = htonl((u32)0);
            i++;
        }
    }
    
    mh->checksum = mospf_checksum(mh);
    
    //check the lsu message and decide if local db should be updated. (trigger: need, periodical: don't need) (if need, call update_db)
    if(local_db_need_upd){
        update_db(msg_lsu);
    }
    
    //broadcast lsu message 
    broadcast_mospf_lsu(NULL, NULL, msg_lsu, len_lsu);
}

int broadcast_mospf_lsu(iface_info_t *need_not_iface, char *iphdr, char *msg_lsu, int len){
    iface_info_t *entry_iface;
    list_for_each_entry(entry_iface, &instance->iface_list, list){
        if(entry_iface == need_not_iface) continue;
        
        mospf_nbr_t *entry_mnbr;
        list_for_each_entry(entry_mnbr, &entry_iface->nbr_list, list){
            char *packet = (char *)malloc(sizeof(struct ether_header) + IP_BASE_HDR_SIZE + len);
            struct ether_header *eh = (struct ether_header *)packet;
            struct iphdr *ih = packet_to_ip_hdr(packet);
            char *msg_lsu_begin = packet + sizeof(struct ether_header) + IP_BASE_HDR_SIZE;
            
            ip_init_hdr(ih, entry_iface->ip, entry_mnbr->nbr_ip, IP_BASE_HDR_SIZE + len, IPPROTO_MOSPF);
            
            memcpy((char *)IP_DATA(ih), msg_lsu, len);
            
            //ip_send_packet(entry_iface, sizeof(struct ether_header) + IP_BASE_HDR_SIZE + len);
            iface_send_packet_by_arp(entry_iface, entry_mnbr->nbr_ip, packet, sizeof(struct ether_header) + IP_BASE_HDR_SIZE + len);
        }
    }
    if(!need_not_iface) free(msg_lsu);
    return 1;
}