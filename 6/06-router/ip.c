#include "ip.h"
#include "icmp.h"
#include "arp.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	  //fprintf(stderr, "TODO: handle ip packet.\n");
    struct ether_header *eh = (struct ether_header *)packet;
    struct iphdr *ih = (struct iphdr *)((char*)packet + sizeof(struct ether_header));
    
    u32 dip = ntohl(ih->daddr);
    
    //ping
    if(dip == iface->ip && ih->protocol == IPPROTO_ICMP){
        //log(DEBUG, "ping iface %d\n", iface->ip);
        icmp_send_packet(packet, len, 0, 0);
        free(packet);
        return;
    }
    
    //ttl check
    ih->ttl -= 1;
    if(ih->ttl <= 0){
        icmp_send_packet(packet, len, 11, 0);
        free(packet);
        return;
    }
    ih->checksum = ip_checksum(ih);
    
    //forward packet
    rt_entry_t* re = longest_prefix_match(dip);
    if(!re){
        icmp_send_packet(packet, len, 3, 0);
        free(packet);
        return;
    }
    else{
        //log(DEBUG, "ping reached here?\n");
        
        u32 gateway = re->gw ? re->gw : dip;
        iface_send_packet_by_arp(re->iface, gateway, packet, len);
    }
}
