#include "mac.h"
#include "log.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

mac_port_map_t mac_port_map;

// initialize mac_port table
void init_mac_port_table()
{
	bzero(&mac_port_map, sizeof(mac_port_map_t));

	for (int i = 0; i < HASH_8BITS; i++) {
		init_list_head(&mac_port_map.hash_table[i]);
	}

	pthread_mutex_init(&mac_port_map.lock, NULL);

	pthread_create(&mac_port_map.thread, NULL, sweeping_mac_port_thread, NULL);
}

// destroy mac_port table
void destory_mac_port_table()
{
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *entry, *q;
	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry_safe(entry, q, &mac_port_map.hash_table[i], list) {
			list_delete_entry(&entry->list);
			free(entry);
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
}

// lookup the mac address in mac_port table
//note: hash mac address by the lowest byte.
//use arg "update" to flush age.
iface_info_t *lookup_port(u8 mac[ETH_ALEN], int update, iface_info_t* newiface)
{
	  // TODO: implement the lookup process here
	  //fprintf(stdout, "TODO: implement the lookup process here.\n");
    int which_list = (int)mac[ETH_ALEN-1];
    
    pthread_mutex_lock(&mac_port_map.lock);
    iface_info_t* res = NULL;
    mac_port_entry_t* entry;
    list_for_each_entry(entry, &mac_port_map.hash_table[which_list], list){
        if(strncmp((char*)mac, (char*)entry->mac, ETH_ALEN) == 0){
            //fprintf(stdout, "found\n");
            res = entry->iface;
            if(update){
                time_t now = time(NULL);
                entry->visited = now;
                entry->iface = newiface;
                //fprintf(stdout, "updated: %s\n", mac);
            }
            break;
        }
    }
    
    pthread_mutex_unlock(&mac_port_map.lock);
    //return NULL if failed to search
    //fprintf(stdout, "lookup. arg is %d\n", update);
    return res;
}

// insert the mac -> iface mapping into mac_port table
void insert_mac_port(u8 mac[ETH_ALEN], iface_info_t *iface)
{
	  // TODO: implement the insertion process here
	  //fprintf(stdout, "TODO: implement the insertion process here.\n");
    //iface is the source interface.
    iface_info_t* st_iface = lookup_port(mac, 1, iface);
    pthread_mutex_lock(&mac_port_map.lock);
    if(!st_iface){
        int which_list = (int)mac[ETH_ALEN-1];
        mac_port_entry_t* newentry = (mac_port_entry_t*)malloc(sizeof(mac_port_entry_t));
        strncpy((char*)newentry->mac, (char*)mac, 6);
        newentry->iface = iface;
        time_t now = time(NULL);
        newentry->visited = now;
        list_add_tail(&newentry->list, &mac_port_map.hash_table[which_list]);
    }
    pthread_mutex_unlock(&mac_port_map.lock);
}

// dumping mac_port table
void dump_mac_port_table()
{
	mac_port_entry_t *entry = NULL;
	time_t now = time(NULL);

	fprintf(stdout, "dumping the mac_port table:\n");
	pthread_mutex_lock(&mac_port_map.lock);
	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry(entry, &mac_port_map.hash_table[i], list) {
			fprintf(stdout, ETHER_STRING " -> %s, %d\n", ETHER_FMT(entry->mac), \
					entry->iface->name, (int)(now - entry->visited));
		}
	}

	pthread_mutex_unlock(&mac_port_map.lock);
}

// sweeping mac_port table, remove the entry which has not been visited in the
// last 30 seconds.
int sweep_aged_mac_port_entry()
{
	  // TODO: implement the sweeping process here
	  //fprintf(stdout, "TODO: implement the sweeping process here.\n");
    pthread_mutex_lock(&mac_port_map.lock);
    mac_port_entry_t* entry, *q;
    int counter = 0;
    for(int i = 0; i < HASH_8BITS; i++){
        list_for_each_entry_safe(entry, q, &mac_port_map.hash_table[i], list){
            time_t now = time(NULL);
            if(now - entry->visited >= MAC_PORT_TIMEOUT){
                list_delete_entry(&entry->list);
                free(entry);
                counter++;
            }
        }
    }
    pthread_mutex_unlock(&mac_port_map.lock);
	  return counter;
}

// sweeping mac_port table periodically, by calling sweep_aged_mac_port_entry
void *sweeping_mac_port_thread(void *nil)
{
	while (1) {
		sleep(1);
		int n = sweep_aged_mac_port_entry();

		//if (n > 0)
			//log(DEBUG, "%d aged entries in mac_port table are removed.", n);
	}

	return NULL;
}
