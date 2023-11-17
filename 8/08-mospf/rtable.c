#include "rtable.h"
#include "ip.h"

//#include "mospf_proto.h"
//#include "mospf_database.h"
//#include "mospf_daemon.h"
//#include "mospf_nbr.h"
//#include "base.h"
//#include "list.h"
//#include "types.h"
//#include "rtable.h"
#include "log.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INFINITY 1000

struct list_head rtable;
pthread_mutex_t rtable_lock;

void init_rtable()
{
	init_list_head(&rtable);
  pthread_mutex_init(&rtable, NULL);
}

rt_entry_t *new_rt_entry(u32 dest, u32 mask, u32 gw, iface_info_t *iface)
{
	rt_entry_t *entry = malloc(sizeof(*entry));
	memset(entry, 0, sizeof(*entry));

	init_list_head(&(entry->list));
	entry->dest = dest;
	entry->mask = mask;
	entry->gw = gw;
	entry->iface = iface;
	strcpy(entry->if_name, iface->name);

	return entry;
}

void add_rt_entry(rt_entry_t *entry)
{
	list_add_tail(&entry->list, &rtable);
}

void remove_rt_entry(rt_entry_t *entry)
{
	list_delete_entry(&entry->list);
	free(entry);
}

void clear_rtable()
{
	struct list_head *head = &rtable, *tmp;
	while (head->next != head) {
		tmp = head->next;
		list_delete_entry(tmp);
		rt_entry_t *entry = list_entry(tmp, rt_entry_t, list);
		free(entry);
	}
}

void print_rtable()
{
	// Print the route records
	fprintf(stderr, "Routing Table:\n");
	fprintf(stderr, "dest\tmask\tgateway\tif_name\n");
	fprintf(stderr, "--------------------------------------\n");
	rt_entry_t *entry = NULL;
	list_for_each_entry(entry, &rtable, list) {
		fprintf(stderr, IP_FMT"\t"IP_FMT"\t"IP_FMT"\t%s\n", \
				HOST_IP_FMT_STR(entry->dest), \
				HOST_IP_FMT_STR(entry->mask), \
				HOST_IP_FMT_STR(entry->gw), \
				entry->if_name);
	}
	fprintf(stderr, "--------------------------------------\n");
}

//topo relevent data
int num_routers;       //number of routers known now
int **topo;           //all path's cost is 1
u32 *rids;            //link index and rid. this link will keep being valid before another call of regenerate_rtable. (I'll prefer to use dict or map XD)

//dijk relevent data
int *vertex_visited;  //set including vertexes that have been calculated
int *dist;            //shortest route temporarily
int *prev;            //previous hop (index in rids)

//for other use
int num_nets;
u32 *all_nets;
int *nets_tackled;

struct rentry_form{
    u32 dst_network;
    u32 dst_mask;
    u32 gw;
    iface_info_t *iface;
};

void get_num_routers(){
    num_routers = 1; //self
    mospf_db_entry_t *entry_mdbe;
    list_for_each_entry(entry_mdbe, &mospf_db, list){
        if(entry_mdbe->rid != instance->router_id)
            num_routers++;
    }
}

void get_all_nets(){
    /*num_nets = 0;
    mospf_db_entry_t *entry_mdbe;
    list_for_each_entry(entry_mdbe, &mospf_db, list){
        if(entry_mdbe->rid == instance->router_id) continue;
        num_nets += entry_mdbe->nadv;
    }
    iface_info_t *entry_iface;
    list_for_each_entry(entry_iface, &instance->iface_list, list){
        if(entry_iface->num_nbr){
            num_nets += entry_iface->num_nbr;
        }
        else{
            num_nets += 2;
        }
    }
    
    num_nets /= 2;*/
    const int MAX_NETS = 500;
    
    num_nets = 0;
    
    nets_tackled = (int *)malloc(sizeof(int) * MAX_NETS);
    for(int i = 0; i < MAX_NETS; i++)
        nets_tackled[i] = 0;
    
    all_nets = (u32 *)malloc(sizeof(u32) * MAX_NETS);
    int ii = 0;
    iface_info_t *entry_iface;
    list_for_each_entry(entry_iface, &instance->iface_list, list){
        if(entry_iface->num_nbr){
            mospf_nbr_t *entry_mnbr;
            list_for_each_entry(entry_mnbr, &entry_iface->nbr_list, list){
                int already = 0;
                for(int m = 0; m < ii; m++){
                    if(all_nets[m] == (entry_mnbr->nbr_ip & entry_mnbr->nbr_mask)){
                        already = 1;
                        break;
                    }
                }
                if(!already){
                    all_nets[ii++] = entry_mnbr->nbr_ip & entry_mnbr->nbr_mask;
                    num_nets += 1;
                }
            }
        }
        else{
            int already = 0;
            for(int m = 0; m < ii; m++){
                if(all_nets[m] == (entry_iface->ip & entry_iface->mask)){
                    already = 1;
                    break;
                }
            }
            if(!already){
                all_nets[ii++] = entry_iface->ip & entry_iface->mask;
                num_nets += 1;
            }
        }
    }
    mospf_db_entry_t *entry_mdbe;
    list_for_each_entry(entry_mdbe, &mospf_db, list){
        if(entry_mdbe->rid == instance->router_id) continue;
        for(int i = 0; i < entry_mdbe->nadv; i++){
            int already = 0;
            for(int m = 0; m < ii; m++){
                if(all_nets[m] == (entry_mdbe->array[i].network)){
                    already = 1;
                    break;
                }
            }
            if(!already){
                all_nets[ii++] = entry_mdbe->array[i].network;
                num_nets++;
            }
        }
    }
}

void print_topo(){
    log(DEBUG, "********************************NOW TOPO IS: **************************");
    for(int i = 0; i < num_routers; i++){
        for(int j = 0; j < num_routers; j++){
            fprintf(stderr, "%d ", topo[i][j]);
        }
        fprintf(stderr, "\n");
    }
    for(int i = 0; i < num_routers; i++){
        fprintf(stderr, "%d: " IP_FMT "\n", i, HOST_IP_FMT_STR(rids[i]));
    }
    log(DEBUG, "********************************END************************************");
}

void init_topo(){ //INFINITY represents no link, 1 represents a link costs 1 (matrix is symmetric because all links are duplex)
    //init rids
    rids = (u32 *)malloc(sizeof(u32) * num_routers);
    int index_router = 1;
    mospf_db_entry_t *entry_mdbe;
    list_for_each_entry(entry_mdbe, &mospf_db, list){
        if(entry_mdbe->rid != instance->router_id)
            rids[index_router++] = entry_mdbe->rid;
    }
    if(index_router != num_routers) log(DEBUG, "fatal");
    assert(index_router == num_routers);
    rids[0] = instance->router_id;
    
    //init topo as INFINITY
    topo = (int **)malloc(sizeof(int *) * num_routers);
    for(int i = 0; i < num_routers; i++){
        topo[i] = (int *)malloc(sizeof(int) * num_routers);
        for(int j = 0; j < num_routers; j++)
            topo[i][j] = INFINITY;
    }
    
    //init topo with db (other routers, then this router)
    //other routers
    list_for_each_entry(entry_mdbe, &mospf_db, list){
        if(entry_mdbe->rid == instance->router_id) continue;
        
        int row_idx = 0;
        for(int i = 1; i < num_routers; i++){
            if(rids[i] == entry_mdbe->rid){
                row_idx = i;
                break;
            }
        }
        assert(row_idx != 0);
        
        for(int i = 0; i < entry_mdbe->nadv; i++){
            int col_idx = -1;
            for(int j = 0; j < num_routers; j++){
                if(rids[j] == entry_mdbe->array[i].rid){
                    col_idx = j;
                    break;
                }
            }
            if(col_idx != -1){ //col_idx == -1 means this nbr of entry_mdbe is 0.0.0.0(none).
                topo[row_idx][col_idx] = 1;
                topo[col_idx][row_idx] = 1;
            }
        }
    }
    //log(DEBUG, "others init succeeded");
    //this router(row_idx is 0)
    /*for(int i = 0; i < num_routers; i++){
        fprintf(stderr, "rids: %d: " IP_FMT "\n", i, HOST_IP_FMT_STR(rids[i]));
    }*/
    iface_info_t *entry_iface;
    list_for_each_entry(entry_iface, &instance->iface_list, list){
        if(!entry_iface->num_nbr) continue;        
        mospf_nbr_t *entry_mnbr;
        list_for_each_entry(entry_mnbr, &entry_iface->nbr_list, list){
            //log(DEBUG, "nbr: " IP_FMT, HOST_IP_FMT_STR(entry_mnbr->nbr_id));
            int col_idx = -1;
            for(int i = 0; i < num_routers; i++){
                if(rids[i] == entry_mnbr->nbr_id){
                    col_idx = i;
                    break;
                }
            }
            //assert(col_idx != -1);
            if(col_idx != -1) {
                topo[0][col_idx] = 1;
                topo[col_idx][0] = 1;
            }
        }
    }
    //log(DEBUG, "this router init succeeded");
    //print_topo();
}

int min_dist(){
    int cost = INFINITY;
    int min_vertex;
    for(int i = 0; i < num_routers; i++){
        if(!vertex_visited[i]){
            if(dist[i] < cost){
                cost = dist[i];
                min_vertex = i;
            }
        }
    }
    
    return min_vertex;
}

void gen_paths_by_dijkstra(){
    //init
    vertex_visited = (int *)malloc(sizeof(int) * num_routers);
    for(int i = 1; i < num_routers; i++) vertex_visited[i] = 0;
    vertex_visited[0] = 1;
    
    dist = (int *)malloc(sizeof(int) * num_routers);
    for(int i = 1; i < num_routers; i++) dist[i] = topo[0][i];
    dist[0] = 0;
    
    prev = (int *)malloc(sizeof(int) * num_routers);
    for(int i = 0; i < num_routers; i++) prev[i] = 0;
    
    //staple loop
    for(int i = 1; i < num_routers; i++){
        int min_vertex = min_dist();
        vertex_visited[min_vertex] = 1;
        
        for(int j = 0; j < num_routers; j++){
            if(!vertex_visited[j] && topo[min_vertex][j] > 0 && dist[min_vertex] + topo[min_vertex][j] < dist[j]){
                dist[j] = dist[min_vertex] + topo[min_vertex][j];
                prev[j] = min_vertex;
            }
        }
    }
}

void print_dist(){
    log(DEBUG, "++++++++++DIST++++++++++++++");
    for(int i = 0; i < num_routers; i++){
        fprintf(stderr, "%d ", dist[i]);
    }
    fprintf(stderr, "\n");
    log(DEBUG, "++++++++++END++++++++++++++");
}

void print_all_nets(){
    log(DEBUG, "++++++++++NETS+++++++++++++");
    for(int i = 0; i < num_nets; i++){
        fprintf(stderr, IP_FMT " ", HOST_IP_FMT_STR(all_nets[i]));
    }
    fprintf(stderr, "\n");
    log(DEBUG, "++++++++++END++++++++++++++");
}

void print_prev(){
    log(DEBUG, "++++++++++PREV+++++++++++++");
    for(int i = 0; i < num_routers; i++){
        fprintf(stderr, "%d ", prev[i]);
    }
    fprintf(stderr, "\n");
    log(DEBUG, "++++++++++END++++++++++++++");
}

void trans_prev_to_rtable(){
    //print_dist();
    //print_all_nets();
    //print_prev();
    struct rentry_form st_rentries[num_nets];
    int idx_st = 0;
    
    for(int i = 0; i < num_routers; i++) vertex_visited[i] = 0;
    for(int i = 0; i < num_routers; i++){
        int min_vertex = -1;
        int cost = INFINITY;
        for(int j = 0; j < num_routers; j++){
            if(!vertex_visited[j] && (dist[j] < cost)){
                min_vertex = j;
                cost = dist[j];
            }
        }
        assert(min_vertex != -1);
        vertex_visited[min_vertex] = 1;
        
        if(min_vertex == 0) {
            iface_info_t *entry_iface;
            list_for_each_entry(entry_iface, &instance->iface_list, list){
                if(entry_iface->num_nbr){
                    mospf_nbr_t *entry_mnbr;
                    list_for_each_entry(entry_mnbr, &entry_iface->nbr_list, list){
                        st_rentries[idx_st].dst_network = entry_mnbr->nbr_ip & entry_mnbr->nbr_mask;
                        //log(DEBUG, "%d", entry_iface->num_nbr);
                        //log(DEBUG, "!!!!!! " IP_FMT, HOST_IP_FMT_STR(st_rentries[idx_st].dst_network));
                        st_rentries[idx_st].dst_mask = entry_mnbr->nbr_mask;
                        st_rentries[idx_st].gw = 0;
                        st_rentries[idx_st].iface = entry_iface;
                        idx_st++;
                        
                        int index_net = -1;
                        for(int k = 0; k < num_nets; k++){
                            if(all_nets[k] == st_rentries[idx_st-1].dst_network){
                                index_net = k;
                                break;
                            }
                        }
                        assert(index_net != -1);
                        nets_tackled[index_net] = 1;
                    }
                }
                else{
                    st_rentries[idx_st].dst_network = entry_iface->ip & entry_iface->mask;
                    //log(DEBUG, "!!!!!! 1'" IP_FMT, HOST_IP_FMT_STR(st_rentries[idx_st].dst_network));
                    st_rentries[idx_st].dst_mask = entry_iface->mask;
                    st_rentries[idx_st].gw = 0;
                    st_rentries[idx_st].iface = entry_iface;
                    idx_st++;
                    
                    int index_net = -1;
                    for(int k = 0; k < num_nets; k++){
                        if(all_nets[k] == st_rentries[idx_st-1].dst_network){
                            index_net = k;
                            break;
                        }
                    }
                    assert(index_net != -1);
                    nets_tackled[index_net] = 1;
                }
            }
        }
        
        else{
            u32 rid_minv = rids[min_vertex];
            int is = 0;
            mospf_db_entry_t *entry_mdbe = NULL;
            list_for_each_entry(entry_mdbe, &mospf_db, list){
                if(entry_mdbe->rid == rid_minv) { is = 1; break; }
            }
            assert(is);
        
            int first_hop = min_vertex;
            while(prev[first_hop] != 0){
                first_hop = prev[first_hop];
            }
            //log(DEBUG, "minv: %d, fhop: %d", min_vertex, first_hop);
            u32 rid_fhop = rids[first_hop];
        
            for(int j = 0; j < entry_mdbe->nadv; j++){
                u32 dst_network = entry_mdbe->array[j].network;
                int index_net = -1;
                for(int k = 0; k < num_nets; k++){
                    if(all_nets[k] == dst_network){
                        index_net = k;
                        break;
                    }
                }
                assert(index_net != -1);
                if(nets_tackled[index_net]) continue;
            
                u32 dst_mask = entry_mdbe->array[j].mask;
                u32 gateway;
                iface_info_t *use_this_iface = NULL;
                list_for_each_entry(use_this_iface, &instance->iface_list, list){
                    int isthis = 0;
                    mospf_nbr_t *entry_mnbr;
                    list_for_each_entry(entry_mnbr, &use_this_iface->nbr_list, list){
                        if(entry_mnbr->nbr_id == rid_fhop){
                            isthis = 1;
                            gateway = entry_mnbr->nbr_ip;
                            break;
                        }
                    }
                    if(isthis) break;
                }
                //assert(is);
            
                //add_rt_entry(new_rt_entry(dst_network, dst_mask, gateway, use_this_iface)); 
                st_rentries[idx_st].dst_network = dst_network;
                st_rentries[idx_st].dst_mask = dst_mask;
                st_rentries[idx_st].gw = gateway;
                st_rentries[idx_st].iface = use_this_iface;
                //log(DEBUG, "%s", use_this_iface->name);
                idx_st++;

                nets_tackled[index_net] = 1;          
            }
        }
    }
    
    pthread_mutex_unlock(&mospf_lock);
    pthread_mutex_lock(&rtable_lock);
    clear_rtable();
    //load_rtable_from_kernel();
    for(int i = 0; i < num_nets; i++){
        add_rt_entry(new_rt_entry(st_rentries[i].dst_network, st_rentries[i].dst_mask, st_rentries[i].gw, st_rentries[i].iface));
    }
    pthread_mutex_unlock(&rtable_lock);
    pthread_mutex_lock(&mospf_lock);
}

void regenerate_rtable(){
    if(rids) free(rids);
    //log(DEBUG, "FREE");
    if(topo){
        for(int i = 0; i < num_routers; i++) free(topo[i]);
        free(topo);
    }
    //log(DEBUG, "FREE");
    if(vertex_visited) free(vertex_visited);
    //log(DEBUG, "FREE");
    if(dist) free(dist);
    //log(DEBUG, "FREE");
    if(prev) free(prev);
    //log(DEBUG, "FREE");
    if(all_nets) free(all_nets);
    //log(DEBUG, "FREE");
    if(nets_tackled) free(nets_tackled);
    //log(DEBUG, "FREE");
    
    //log(DEBUG, "here0");
    get_num_routers();
    //log(DEBUG, "here1");
    get_all_nets();
    //log(DEBUG, "here2");
    init_topo();
    //log(DEBUG, "here3");
    gen_paths_by_dijkstra();
    //log(DEBUG, "here4");
    trans_prev_to_rtable();
    //log(DEBUG, "here5");
    
    print_rtable();
}
