#include "nat.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "rtable.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>

static struct nat_table nat;

// get the interface from iface name
static iface_info_t *if_name_to_iface(const char *if_name)
{
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (strcmp(iface->name, if_name) == 0)
			return iface;
	}

	log(ERROR, "Could not find the desired interface according to if_name '%s'", if_name);
	return NULL;
}

// determine the direction of the packet, DIR_IN / DIR_OUT / DIR_INVALID
static int get_packet_direction(char *packet)
{
	  //fprintf(stdout, "TODO: determine the direction of this packet.\n");
    int res = DIR_INVALID;
    struct iphdr *ih = packet_to_ip_hdr(packet);
    rt_entry_t *srentry = longest_prefix_match(ntohl(ih->saddr));
    rt_entry_t *drentry = longest_prefix_match(ntohl(ih->daddr));
    if((ntohl(ih->daddr) == nat.external_iface->ip) && (srentry->iface == nat.external_iface))
        res = DIR_IN;
    if((srentry->iface == nat.internal_iface) && (drentry->iface == nat.external_iface))
        res = DIR_OUT;
    
    return res;
}

//local_ip is: nat.external_iface->ip (dir == IN),
//             some internal source ip (dir == OUT).
static struct nat_mapping *lookup_mapping(u32 local_ip, u16 local_port, u32 remote_ip, u16 remote_port, int dir){
    pthread_mutex_lock(&nat.lock);
    struct nat_mapping *res = NULL;
    assert((dir == DIR_IN) || (dir == DIR_OUT));
    
    u8 which_list = hash8_ip_and_port(remote_ip, remote_port);
    struct nat_mapping *entry_nmap;
    if(dir == DIR_IN){
        list_for_each_entry(entry_nmap, &nat.nat_mapping_list[which_list], list){
            if((entry_nmap->external_ip == local_ip) && (entry_nmap->external_port == local_port)){
                res = entry_nmap;
                break;
            }
        }
    }
    else{
        list_for_each_entry(entry_nmap, &nat.nat_mapping_list[which_list], list){
            if((entry_nmap->internal_ip == local_ip) && (entry_nmap->internal_port == local_port)){
                res = entry_nmap;
                break;
            }
        }
    }
    
    pthread_mutex_unlock(&nat.lock);
    return res;
}

u16 assign_external_port(){
    u16 res = 0;
    for(int i = NAT_PORT_MIN; i <= NAT_PORT_MAX; i++){
        if(!nat.assigned_ports[i]){
            res = (u16)i;
            nat.assigned_ports[i] = 1;
            break;
        }
    }
    return res;
}

struct nat_mapping *estab_mapping(u32 local_ip, u16 local_port, u32 remote_ip, u16 remote_port, int dir){
    pthread_mutex_lock(&nat.lock);
    struct nat_mapping *res = NULL;
    assert((dir == DIR_IN) || (dir == DIR_OUT));
    
    u8 which_list = hash8_ip_and_port(remote_ip, remote_port);
    if(dir == DIR_IN){
        struct dnat_rule *entry_rule;
        int found = 0;
        list_for_each_entry(entry_rule, &nat.rules, list){
            if((entry_rule->external_ip == local_ip) && (entry_rule->external_port == local_port)){
                found = 1;
                break;
            }
        }
        if(!found){
            pthread_mutex_unlock(&nat.lock);
            return NULL;
        }
        
        res = (struct nat_mapping *)malloc(sizeof(struct nat_mapping));
        bzero((char *)res, sizeof(struct nat_mapping));
        res->remote_ip = remote_ip;
        res->remote_ip = remote_port;
        res->internal_ip = entry_rule->internal_ip;
        res->internal_port = entry_rule->internal_port;
        res->external_ip = local_ip;
        res->external_port = local_port;
        res->update_time = time(NULL);
        list_add_tail(&res->list, &nat.nat_mapping_list[which_list]);
        pthread_mutex_unlock(&nat.lock);
        return res;
    }
    
    else{
        res = (struct nat_mapping *)malloc(sizeof(struct nat_mapping));
        bzero((char *)res, sizeof(struct nat_mapping));
        res->remote_ip = remote_ip;
        res->remote_port = remote_port;
        res->internal_ip = local_ip;
        res->internal_port = local_port;
        res->external_ip = nat.external_iface->ip;
        res->external_port = assign_external_port();
        if(!res->external_port) return NULL;
        res->update_time = time(NULL);
        list_add_tail(&res->list, &nat.nat_mapping_list[which_list]);
        pthread_mutex_unlock(&nat.lock);
        return res;
    }
    pthread_mutex_unlock(&nat.lock);
    return res;
}

// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t *iface, char *packet, int len, int dir)
{
	  //fprintf(stdout, "TODO: do translation for this packet.\n");
    struct iphdr *ih = packet_to_ip_hdr(packet);
    struct tcphdr *th = packet_to_tcp_hdr(packet);
    if((dir != DIR_IN) && (dir != DIR_OUT))
        return;
    
    struct nat_mapping *map;
    if(dir == DIR_IN){
        map = lookup_mapping(ntohl(ih->daddr), ntohs(th->dport), ntohl(ih->saddr), ntohs(th->sport), DIR_IN);
        if(!map && (th->flags & TCP_SYN)){
            map = estab_mapping(ntohl(ih->daddr), ntohs(th->dport), ntohl(ih->saddr), ntohs(th->sport), DIR_IN);
            if(map) printf("ok\n");
        }
        if(!map){
            printf("not ok\n");
            icmp_send_packet(packet, len, 3, 1);
            free(packet);
            return;
        }
        
        ih->daddr = htonl(map->internal_ip);
        th->dport = htons(map->internal_port);
        ih->checksum = ip_checksum(ih);
        th->checksum = tcp_checksum(ih, th);
        
        u32 seq_end = tcp_seq_end(ih, th);
        u32 ack = ntohl(th->ack);
        if(seq_end > map->conn.external_seq_end)
            map->conn.external_seq_end = seq_end;
        if(ack > map->conn.external_ack)
            map->conn.external_ack = ack;
        if(th->flags & TCP_FIN)
            map->conn.external_fin = 1;
        if(th->flags & TCP_RST)
            map->conn.rst = 1;
    }
    else{
        map = lookup_mapping(ntohl(ih->saddr), ntohs(th->sport), ntohl(ih->daddr), ntohs(th->dport), DIR_OUT);
        if(!map && (th->flags & TCP_SYN)){
            map = estab_mapping(ntohl(ih->saddr), ntohs(th->sport), ntohl(ih->daddr), ntohs(th->dport), DIR_OUT);
            //if(map) printf("ok\n");
        }
        if(!map){
            icmp_send_packet(packet, len, 3, 1);
            free(packet);
            return;
        }
        
        ih->saddr = htonl(map->external_ip);
        th->sport = htons(map->external_port);
        ih->checksum = ip_checksum(ih);
        th->checksum = tcp_checksum(ih, th);
        
        u32 seq_end = tcp_seq_end(ih, th);
        u32 ack = ntohl(th->ack);
        if(seq_end > map->conn.internal_seq_end)
            map->conn.internal_seq_end = seq_end;
        if(ack > map->conn.internal_ack)
            map->conn.internal_ack = ack;
        if(th->flags & TCP_FIN)
            map->conn.internal_fin = 1;
        if(th->flags & TCP_RST)
            map->conn.rst = 1;
    }
    
    //fprintf(stderr, "forward it\n");
    //fprintf(stderr, "ip: %u, port: %hu\n", ntohl(ih->daddr), ntohs(th->dport));
    ip_forward_packet(ntohl(ih->daddr), packet, len);
}

void nat_translate_packet(iface_info_t *iface, char *packet, int len)
{
	int dir = get_packet_direction(packet);
  /*if(dir == DIR_IN) log(DEBUG, "IN");
  else if(dir == DIR_OUT) log(DEBUG, "OUT");
  else log(DEBUG, "ERR");*/
	if (dir == DIR_INVALID) {
		log(ERROR, "invalid packet direction, drop it.");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		return ;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (ip->protocol != IPPROTO_TCP) {
		log(ERROR, "received non-TCP packet (0x%0hhx), drop it", ip->protocol);
		free(packet);
		return ;
	}

	do_translation(iface, packet, len, dir);
}

// check whether the flow is finished according to FIN bit and sequence number
// XXX: seq_end is calculated by `tcp_seq_end` in tcp.h
static int is_flow_finished(struct nat_connection *conn)
{
    return (conn->internal_fin && conn->external_fin) && \
            (conn->internal_ack >= conn->external_seq_end) && \
            (conn->external_ack >= conn->internal_seq_end);
}

// nat timeout thread: find the finished flows, remove them and free port
// resource
void *nat_timeout()
{
	  while (1) {
		    //fprintf(stdout, "TODO: sweep finished flows periodically.\n");
        sleep(1);
        pthread_mutex_lock(&nat.lock);
        time_t now = time(NULL);
        for(int i = 0; i < HASH_8BITS; i++){
            struct nat_mapping *entry_nmap, *q;
            list_for_each_entry_safe(entry_nmap, q, &nat.nat_mapping_list[i], list){
                if((now - entry_nmap->update_time > TCP_ESTABLISHED_TIMEOUT) || is_flow_finished(&entry_nmap->conn) || entry_nmap->conn.rst){
                    list_delete_entry(&entry_nmap->list);
                    free(entry_nmap);
                }
            }
        }
        pthread_mutex_unlock(&nat.lock);
	  }

	  return NULL;
}

int parse_config(const char *filename)
{
    //fprintf(stdout, "TODO: parse config file, including i-iface, e-iface (and dnat-rules if existing).\n");
    FILE *fp = fopen(filename, "r");
    if(!fp) return -1;
    pthread_mutex_lock(&nat.lock);
    
    char thisline[100];
    while(fgets(thisline, 100, fp)){
        char operation[20];
        sscanf(thisline, "%[^:]", operation);
        if(strncmp(operation, "internal-iface", 20) == 0){
            char name[20];
            sscanf(thisline, "%s %s", operation, name);
            nat.internal_iface = if_name_to_iface(name);
            //printf("iif. name: %s\n", name);
        }
        else if(strncmp(operation, "external-iface", 20) == 0){
            char name[20];
            sscanf(thisline, "%s %s", operation, name);
            nat.external_iface = if_name_to_iface(name);
            //printf("eif. name: %s\n", name);
        }
        else if(strncmp(operation, "dnat-rules", 20) == 0){
            char expair[30], arrow[2], inpair[30];
            sscanf(thisline, "%s %s %s %s", operation, expair, arrow, inpair);
            //printf("%s\n", expair);
            //printf("%s\n", inpair);
            struct dnat_rule *new_rule = (struct dnat_rule *)malloc(sizeof(struct dnat_rule));
            u32 exip3, exip2, exip1, exip0, inip3, inip2, inip1, inip0;
            u16 export, inport;
            sscanf(expair, "%d.%d.%d.%d:%hd", &exip3, &exip2, &exip1, &exip0, &export);
            sscanf(inpair, "%d.%d.%d.%d:%hd", &inip3, &inip2, &inip1, &inip0, &inport);
            u32 exip = (exip3 << 24) | (exip2 << 16) | (exip1 << 8) | exip0;
            u32 inip = (inip3 << 24) | (inip2 << 16) | (inip1 << 8) | inip0;
            new_rule->external_ip = exip;
            new_rule->internal_ip = inip;
            new_rule->external_port = export;
            new_rule->internal_port = inport;
            list_add_tail(&new_rule->list, &nat.rules);
            //printf("rule. %d.%d.%d.%d:%hd -> %d.%d.%d.%d:%hd\n", exip3, exip2, exip1, exip0, export, inip3, inip2, inip1, inip0, inport);
        }
    }
    
    pthread_mutex_unlock(&nat.lock);
    return 1;
}

// initialize
void nat_init(const char *config_file)
{
	memset(&nat, 0, sizeof(nat));

	for (int i = 0; i < HASH_8BITS; i++)
		init_list_head(&nat.nat_mapping_list[i]);

	init_list_head(&nat.rules);

	// seems unnecessary
	memset(nat.assigned_ports, 0, sizeof(nat.assigned_ports));

	parse_config(config_file);
  //printf("done.\n");

	pthread_mutex_init(&nat.lock, NULL);

	pthread_create(&nat.thread, NULL, nat_timeout, NULL);
}

void nat_exit()
{
	  //fprintf(stdout, "TODO: release all resources allocated.\n");
    for(int i = 0; i < HASH_8BITS; i++){
        struct nat_mapping *entry_nmap, *q;
        list_for_each_entry_safe(entry_nmap, q, &nat.nat_mapping_list[i], list){
            list_delete_entry(&entry_nmap->list);
            free(entry_nmap);
        }
    }
    
    struct dnat_rule *entry_rule, *q;
    list_for_each_entry_safe(entry_rule, q, &nat.rules, list){
        list_delete_entry(&entry_rule->list);
        free(entry_rule);
    }
    
    pthread_mutex_destroy(&nat.lock);
    pthread_kill(nat.thread, SIGKILL);
}
