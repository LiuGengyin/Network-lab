#include "mospf_database.h"
#include "ip.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct list_head mospf_db;

void init_mospf_db()
{
	init_list_head(&mospf_db);
}

void print_mospf_db() {
	
	log(DEBUG, "************************THIS UPDATE: ***************************\n");

	mospf_db_entry_t * entry_mdbe;
	list_for_each_entry(entry_mdbe, &mospf_db, list) {
    log(DEBUG, "----------------------------------------------------------------\n");
    for(int i = 0; i < entry_mdbe->nadv; i++){
        log(DEBUG, "thisrid: " IP_FMT ", network: " IP_FMT ", mask: %x, neighbour: " IP_FMT "\n", HOST_IP_FMT_STR(entry_mdbe->rid), HOST_IP_FMT_STR(entry_mdbe->array[i].network), entry_mdbe->array[i].mask, HOST_IP_FMT_STR(entry_mdbe->array[i].rid));
    }
    log(DEBUG, "----------------------------------------------------------------\n");
	}
	log(DEBUG, "************************END*************************************\n");
}

void update_db(char *lsu_msg){
    //lsu_msg should not include etherhdr or iphdr.
    struct mospf_hdr *mhdr = (struct mospf_hdr *)lsu_msg;
    struct mospf_lsu *mlsu = (struct mospf_lsu *)(lsu_msg + MOSPF_HDR_SIZE);
    int nadv = ntohl(mlsu->nadv);
    struct mospf_lsa *mlsas = (struct mospf_lsa *)(lsu_msg + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE);
    
    //if no match dbentry, malloc one; else check the seq, update it.
    mospf_db_entry_t *entry_mdbe, *found;
    found = NULL;
    list_for_each_entry(entry_mdbe, &mospf_db, list){
        if(entry_mdbe->rid == ntohl(mhdr->rid)){
            found = entry_mdbe;
            break;
        }
    }
    
    if(found){
        if(ntohl(mlsu->seq) > found->seq){
            found->seq = ntohl(mlsu->seq);
            found->nadv = nadv;
            found->alive = 0;
            if(found->array) free(found->array);
            found->array = (struct mospf_lsa *)malloc(nadv * MOSPF_LSA_SIZE);
        }
        else return;
    }
    else{
        found = (mospf_db_entry_t *)malloc(sizeof(mospf_db_entry_t));
        found->rid = ntohl(mhdr->rid);
        found->seq = ntohl(mlsu->seq);
        found->nadv = nadv;
        found->alive = 0;
        found->array = (struct mospf_lsa *)malloc(nadv * MOSPF_LSA_SIZE);
        list_add_tail(&found->list, &mospf_db);
    }
    for(int i = 0; i < nadv; i++){
        found->array[i].network = ntohl(mlsas[i].network);
        found->array[i].mask = ntohl(mlsas[i].mask);
        found->array[i].rid = ntohl(mlsas[i].rid);
    }
    
    //print_mospf_db();
}