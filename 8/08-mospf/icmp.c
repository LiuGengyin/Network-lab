#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	  //fprintf(stderr, "TODO: malloc and send icmp packet.\n");
    struct iphdr *in_ih = packet_to_ip_hdr(in_pkt);
    char *message; //when this process done, the ether_header part of message will not be designated. it will be assembled by send_by_arp's query.
    u32 dip = ntohl(in_ih->saddr);
    u32 sip;
    u16 msg_ip_tot_len;
    u8 proto = IPPROTO_ICMP;
    pthread_mutex_lock(&rtable_lock);
    rt_entry_t *re = longest_prefix_match(dip);
    if(!re){log(DEBUG, "icmp: no default route\n"); return;}
    sip = re->iface->ip;
    
    int icmp_len;
    int msg_len;
    if(type == ICMP_DEST_UNREACH || type == ICMP_TIME_EXCEEDED){
        icmp_len = ICMP_HDR_SIZE + IP_HDR_SIZE(in_ih) + ICMP_COPIED_DATA_LEN;
    }
    else if(type == ICMP_ECHOREPLY){
        icmp_len = ntohs(in_ih->tot_len) - IP_HDR_SIZE(in_ih);
    }
    msg_len = sizeof(struct ether_header) + IP_BASE_HDR_SIZE + icmp_len;
    
    message = (char *)malloc(msg_len);
    
    struct iphdr *out_ih = packet_to_ip_hdr(message);
    
    msg_ip_tot_len = IP_BASE_HDR_SIZE + icmp_len;
    if(type == ICMP_DEST_UNREACH || type == ICMP_TIME_EXCEEDED){
        ip_init_hdr(out_ih, sip, dip, msg_ip_tot_len, proto);
    }
    else if(type == ICMP_ECHOREPLY){
        ip_init_hdr(out_ih, sip, dip, msg_ip_tot_len, proto);
    }
    
    struct icmphdr *out_icmphdr = (struct icmphdr *)IP_DATA(out_ih);
    if(type == ICMP_DEST_UNREACH || type == ICMP_TIME_EXCEEDED){
        out_icmphdr->icmp_identifier = 0;
        out_icmphdr->icmp_sequence = 0;
        memcpy(IP_DATA(out_ih) + ICMP_HDR_SIZE, (char *)in_ih, icmp_len - ICMP_HDR_SIZE);  
    }
    else if(type == ICMP_ECHOREPLY){
        memcpy(out_icmphdr, (struct icmphdr *)IP_DATA(in_ih), icmp_len);
    }
    
    out_icmphdr->type = type;
    out_icmphdr->code = code;
    out_icmphdr->checksum = icmp_checksum(out_icmphdr, icmp_len);
    
    pthread_mutex_unlock(&rtable_lock);
    ip_send_packet(message, msg_len);
}
