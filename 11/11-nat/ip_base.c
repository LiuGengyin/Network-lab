#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"

#include "log.h"

#include <stdio.h>
#include <stdlib.h>

// initialize ip header 
void ip_init_hdr(struct iphdr *ip, u32 saddr, u32 daddr, u16 len, u8 proto)
{
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons(len);
	ip->id = rand();
	ip->frag_off = htons(IP_DF);
	ip->ttl = DEFAULT_TTL;
	ip->protocol = proto;
	ip->saddr = htonl(saddr);
	ip->daddr = htonl(daddr);
	ip->checksum = ip_checksum(ip);
}

// lookup in the routing table, to find the entry with the same and longest prefix.
// the input address is in host byte order
rt_entry_t *longest_prefix_match(u32 dst)
{
	  //fprintf(stderr, "TODO: longest prefix match for the packet.\n");
    //postulates that dst is of host order
    rt_entry_t *res = NULL;
	  rt_entry_t *entry;
    u32 mmask = 0;
    list_for_each_entry(entry, &rtable, list){
        if((dst & entry->mask) == (entry->dest & entry->mask)){
            if(entry->mask > mmask){
                mmask = entry->mask;
                res = entry;
            }
        }
    }
    
    if(!res){
        list_for_each_entry(entry, &rtable, list){
            if(entry->dest == 0){
                res = entry;
                break;
            }
        }
    }
    
    if(!res) log(DEBUG, "ip: dst doesn't match -- no default route\n");
    return res;
}

void ip_forward_packet(u32 dst, char* packet, int len){
    struct iphdr *ih = packet_to_ip_hdr(packet);
    ih->ttl -= 1;
    if(ih->ttl <= 0){
        icmp_send_packet(packet, len, 11, 0);
        free(packet);
        return;
    } 
    ih->checksum = ip_checksum(ih);
    
    //pthread_mutex_lock(&rtable_lock);
    rt_entry_t* re = longest_prefix_match(dst);
    if(!re){
        icmp_send_packet(packet, len, 3, 0);
        free(packet);
        return;
    }
    else{
        //log(DEBUG, "ping reached here?\n");
        u32 gateway = re->gw ? re->gw : dst;
        iface_send_packet_by_arp(re->iface, gateway, packet, len);
    }
    //pthread_mutex_unlock(&rtable_lock);
}

// send IP packet
//
// Different from forwarding packet, ip_send_packet sends packet generated by
// router itself. This function is used to send ICMP packets.
void ip_send_packet(char *packet, int len)
{
	  //fprintf(stderr, "TODO: send ip packet.\n");
    //struct ether_header *eh = (struct ether_header *)packet;
    struct iphdr *ih = packet_to_ip_hdr(packet);
    
    u32 dip = ntohl(ih->daddr);
    rt_entry_t *re = longest_prefix_match(dip);
    if(!re){log(DEBUG, "icmp: no default route\n"); return;}
    
    u32 gateway = re->gw ? re->gw : dip;
    //log(DEBUG, "re->gw: %d\n", re->gw);
    //log(DEBUG, "gateway: %d\n", gateway);
    
    iface_send_packet_by_arp(re->iface, gateway, packet, len);
}