#include "base.h"
#include <stdio.h>

// XXX ifaces are stored in instace->iface_list
extern ustack_t *instance;

extern void iface_send_packet(iface_info_t *iface, const char *packet, int len);

void broadcast_packet(iface_info_t *iface, const char *packet, int len)
{
	  // TODO: broadcast packet 
    //fprintf(stdout, "TODO: broadcast packet.\n");
    int rx_fd = iface->fd;
    iface_info_t* entry;
    list_for_each_entry(entry, &instance->iface_list, list){
        if(entry->fd != rx_fd){
            iface_send_packet(entry, packet, len);
        }
    }
}
