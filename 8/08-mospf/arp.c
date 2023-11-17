#include "arp.h"
#include "base.h"
#include "types.h"
#include "ether.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "log.h"

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	  //fprintf(stderr, "TODO: send arp request when lookup failed in arpcache.\n");
    //log(DEBUG, "send arp req from iface %d, dst_ip is %d\n", iface->ip, dst_ip);
    struct ether_header *eh = (struct ether_header *)malloc(sizeof(struct ether_header));
    memset(eh->ether_dhost, 0xff, ETH_ALEN);
    memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
    eh->ether_type = htons(0x0806);
    
    struct ether_arp *ea = (struct ether_arp *)malloc(sizeof(struct ether_arp));
    ea->arp_hrd = htons(ARPHRD_ETHER);
    ea->arp_pro = htons(0x0800);
    ea->arp_hln = 0x6;
    ea->arp_pln = 0x4;
    ea->arp_op = htons(ARPOP_REQUEST);
    memcpy(ea->arp_sha, iface->mac, ETH_ALEN);
    ea->arp_spa = htonl(iface->ip);
    bzero(ea->arp_tha, ETH_ALEN);
    ea->arp_tpa = htonl(dst_ip);
    
    char *packet = (char *)malloc(sizeof(struct ether_header) + sizeof(struct ether_arp));
    memcpy(packet, (char *)eh, sizeof(struct ether_header));
    memcpy(packet+sizeof(struct ether_header), (char *)ea, sizeof(struct ether_arp));
    iface_send_packet(iface, packet, sizeof(struct ether_header) + sizeof(struct ether_arp));
    free(eh); free(ea);
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	  //fprintf(stderr, "TODO: send arp reply when receiving arp request.\n");
    //postulates that req_hdr is of net order
    struct ether_header *eh = (struct ether_header *)malloc(sizeof(struct ether_header));
    memcpy(eh->ether_dhost, req_hdr->arp_sha, ETH_ALEN);
    memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
    eh->ether_type = htons(0x0806);
    
    struct ether_arp *ea = (struct ether_arp *)malloc(sizeof(struct ether_arp));
    ea->arp_hrd = htons(ARPHRD_ETHER);
    ea->arp_pro = htons(0x0800);
    ea->arp_hln = 0x6;
    ea->arp_pln = 0x4;
    ea->arp_op = htons(ARPOP_REPLY);
    memcpy(ea->arp_sha, iface->mac, ETH_ALEN);
    ea->arp_spa = htonl(iface->ip);
    memcpy(ea->arp_tha, req_hdr->arp_sha, ETH_ALEN);
    ea->arp_tpa = req_hdr->arp_spa;
    
    char *packet = (char *)malloc(sizeof(struct ether_header) + sizeof(struct ether_arp));
    memcpy(packet, (char *)eh, sizeof(struct ether_header));
    memcpy(packet+sizeof(struct ether_header), (char *)ea, sizeof(struct ether_arp));
    iface_send_packet(iface, packet, sizeof(struct ether_header) + sizeof(struct ether_arp));
    free(eh); free(ea);
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	  //fprintf(stderr, "TODO: process arp packet: arp request & arp reply.\n");
    
    if(!(len == sizeof(struct ether_header) + sizeof(struct ether_arp))) 
        log(DEBUG, "arp packet length does not correspond with expectation\n");
    struct ether_arp *ea = (struct ether_arp *)((char *)packet + sizeof(struct ether_header));
    //tackle arp request
    if(ntohs(ea->arp_op) == ARPOP_REQUEST){
        if(iface->ip == ntohl(ea->arp_tpa)){
            arp_send_reply(iface, ea);
        }
    }
    //tackle arp reply
    else if(ntohs(ea->arp_op) == ARPOP_REPLY){
        //log(DEBUG, "iface %d got reply\n", iface->ip);
        if(ntohl(ea->arp_tpa) == iface->ip && memcmp(iface->mac, ea->arp_tha, ETH_ALEN) == 0){
            //log(DEBUG, "arpcache_insert. tpa = %d, spa = %d\n", ntohl(ea->arp_tpa), ntohl(ea->arp_spa));
            arpcache_insert(ntohl(ea->arp_spa), ea->arp_sha);
        }
    }
    else log(DEBUG, "arp operation not supplied\n");
    free(packet);
}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
// attention: dst_ip is the ip you are willing to lookup, not the ip which packet is heading to.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
  //if(iface->ip == 167772417) log(DEBUG, "got it in send_by_arp\n");
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		//log(DEBUG, "found the mac of %x, send this packet", dst_ip);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	}
	else {
		//log(DEBUG, "lookup %x failed, pend this packet", dst_ip);
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
