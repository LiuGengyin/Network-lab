#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"

#include "mospf_proto.h"
#include "mospf_daemon.h"

#include "log.h"

#include <stdlib.h>
#include <assert.h>

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	u32 daddr = ntohl(ip->daddr);
	if (daddr == iface->ip) {
		if (ip->protocol == IPPROTO_ICMP) {
			struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip);
			if (icmp->type == ICMP_ECHOREQUEST) {
				icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
			}
		}
		else if (ip->protocol == IPPROTO_MOSPF) {
			handle_mospf_packet(iface, packet, len); //note that the modification of ip header(ttl) should be in handle_mospf_packet.
		}

		free(packet);
	}
	else if (ip->daddr == htonl(MOSPF_ALLSPFRouters)) {
		assert(ip->protocol == IPPROTO_MOSPF);
		handle_mospf_packet(iface, packet, len);

		free(packet);
	}
	else {
		ip_forward_packet(daddr, packet, len);
	}
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
    
    pthread_mutex_lock(&rtable_lock);
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
    pthread_mutex_unlock(&rtable_lock);
}
