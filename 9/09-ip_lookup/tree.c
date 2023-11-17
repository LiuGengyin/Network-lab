#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

node_t *root;

struct st{
    char ip[16];
    uint32_t mask;
    int port;
};

// return an array of ip represented by an unsigned integer, the length of array is TEST_SIZE
uint32_t* read_test_data(const char* lookup_file){
    //fprintf(stderr,"TODO:%s",__func__);
    uint32_t *ip_vec = (uint32_t *)malloc(TEST_SIZE * sizeof(uint32_t));
    FILE* fp = fopen(lookup_file, "r");
    for(int i = 0; i < TEST_SIZE; i++){
        uint32_t ip3, ip2, ip1, ip0, ip;
        fscanf(fp, "%d.%d.%d.%d\n", &ip3, &ip2, &ip1, &ip0);
        ip = (ip3 << 24) | (ip2 << 16) | (ip1 << 8) | ip0;
        ip_vec[i] = ip;
    }
    
    return ip_vec;
}

void destroy_tree(node_t *thisroot){
    if(!thisroot) return;
    destroy_tree(thisroot->lchild);
    destroy_tree(thisroot->rchild);
    free(thisroot);
}

node_t *retrieve_this_entry(uint32_t ip, int mask, int port){
    assert((ip & !mask) == 0);
    if(!root) return NULL;
    node_t *current_node = root;
    uint32_t remnant_bits = ip >> (32-mask); //mask bits valid remaining
    for(int i = 0; i < mask; i++){
        uint32_t this_bit = (remnant_bits >> (mask-i-1)) & 1LU;
        assert(this_bit == 0 || this_bit == 1);
        assert(this_bit == ((ip & (1LU<<(31-i))) >> (31-i)));
        if(this_bit == LEFT){
            if(!current_node->lchild){
                current_node->lchild = (node_t *)malloc(sizeof(node_t));
                current_node->lchild->type = I_NODE;
                current_node->lchild->port = -1;
                current_node->lchild->lchild = current_node->lchild->rchild = NULL;
            } 
            current_node = current_node->lchild;
        }
        else{
            if(!current_node->rchild){
                current_node->rchild = (node_t *)malloc(sizeof(node_t));
                current_node->rchild->type = I_NODE;
                current_node->rchild->port = -1;
                current_node->rchild->lchild = current_node->rchild->rchild = NULL; 
            }
            current_node = current_node->rchild;
        }
        
        if(i == mask-1){
            current_node->type = M_NODE;
            current_node->port = port;
        }
    }
    
    assert(current_node != root);
    return current_node;
}

/*int cmp(const void* a1, const void* a2) {
	  struct st* s1 = (struct st*)a1;
	  struct st* s2 = (struct st*)a2;
	  if (s1->mask < s2->mask) return -1;
	  else if (s1->mask == s2->mask) return 0;
	  else return 1;
}*/

void print_tree(node_t *thisroot, int depth){ //root, 0
    if(!thisroot) return;
    if(thisroot == root)
        fprintf(stderr, "type\tport\n");
    node_t *cur = thisroot;
    for(int i = 0; i < depth; i++)
        fprintf(stderr, "\t");
    fprintf(stderr, "%d\t%d\n", cur->type, cur->port);
    print_tree(thisroot->lchild, depth+1);
    print_tree(thisroot->rchild, depth+1);
}

// Constructing an basic trie-tree to lookup according to `forward_file`
void create_tree(const char* forward_file){
    //fprintf(stderr,"TODO:%s",__func__);
    destroy_tree(root);
    assert(!root);
    root = (node_t *)malloc(sizeof(node_t));
    root->type = I_NODE;
    root->port = -1;
    root->lchild = NULL;
    root->rchild = NULL;
    
    FILE* fp = fopen(forward_file, "r");
	  struct st* sts = (struct st*)malloc(TRAIN_SIZE * sizeof(struct st));
	  for (int i = 0; i < TRAIN_SIZE; i++) {
		  char ip[15];
		  int mask;
		  int port;
		  fscanf(fp, "%s %d %d\n", ip, &mask, &port);
		  strcpy(sts[i].ip, ip);
		  sts[i].mask = mask;
		  sts[i].port = port;
	  }
	  fclose(fp);
	  //qsort(sts, TEST_SIZE, sizeof(struct st), cmp);
     
    for(int i = 0; i < TRAIN_SIZE; i++){
        uint32_t ip3, ip2, ip1, ip0;
        uint32_t ip;
        sscanf(sts[i].ip, "%d.%d.%d.%d", &ip3, &ip2, &ip1, &ip0);
        ip = (ip3 << 24) | (ip2 << 16) | (ip1 << 8) | ip0;
        //fprintf(stderr, "%x\n", ip);
        retrieve_this_entry(ip, sts[i].mask, sts[i].port);
    }
    
    free(sts);
    //print_tree(root, 0);
}

int ip_prefix_cmp(uint32_t tip){
    int res = -1;
    if(!root) return res;
    int checked_bit = 0;
    node_t *cur_node = root;
    while(1){
        if(cur_node->type == M_NODE){
            res = cur_node->port;
        }
        uint32_t this_bit = (tip >> (31-checked_bit)) & 1LU;
        checked_bit++;
        if(this_bit == LEFT){
            cur_node = cur_node->lchild;
            if(!cur_node) break;
        }
        else{
            cur_node = cur_node->rchild;
            if(!cur_node) break;
        }
    }
    
    return res;
}

// Look up the ports of ip in file `ip_to_lookup.txt` using the basic tree, input is read from `read_test_data` func 
int *lookup_tree(uint32_t* ip_vec){
    //fprintf(stderr,"TODO:%s",__func__);
    int *res_vec = (int *)malloc(TEST_SIZE * sizeof(int));
    
    for(int i = 0; i < TEST_SIZE; i++){
        //lookup
        res_vec[i] = ip_prefix_cmp(ip_vec[i]);
    }
    
    return res_vec;
}

struct dpt_info{
    node_adv_t* ptr;
    int history_port;
};

node_adv_t *root_adv;
struct dpt_info *direct_pt;

void destroy_tree_adv(node_adv_t *thisroot){
    if(direct_pt) free(direct_pt);
    if(!thisroot) return;
    for(int i = 0; i < 4; i++){
        destroy_tree_adv(thisroot->childs[i]);
    }
    free(thisroot);
}

void retrieve_this_entry_adv(uint32_t ip, int mask, int port){
    if(!root_adv) return;
    node_adv_t *current_node = root_adv;
    uint32_t remnant_bits = ip >> (32-mask);
    int is_odd = mask % 2;
    
    for(int i = 0; i < mask/2; i++){
        uint32_t this_2_bits = (remnant_bits >> (mask-2*i-2)) & 3LU;
        assert(this_2_bits >= 0 && this_2_bits <= 3);
        if(!current_node->childs[this_2_bits]){
            current_node->childs[this_2_bits] = (node_adv_t *)malloc(sizeof(node_adv_t));
            current_node->childs[this_2_bits]->type = I_NODE;
            current_node->childs[this_2_bits]->port_odd = current_node->childs[this_2_bits]->port_even = -1;
            for(int j = 0; j < 4; j++)
              current_node->childs[this_2_bits]->childs[j] = NULL;
        }
        current_node = current_node->childs[this_2_bits];
        
        if(!is_odd){
            if(i == mask/2-1){
                current_node->type = M_NODE;
                current_node->port_even = port;
            }
        }
    }
    
    if(is_odd){
        uint32_t this_bit = remnant_bits & 1LU;
        for(int i = 2*this_bit; i < this_bit*2+2; i++){
            if(!current_node->childs[i]){
                current_node->childs[i] = (node_adv_t *)malloc(sizeof(node_adv_t));
                current_node->childs[i]->type = M_NODE;
                current_node->childs[i]->port_odd = port;
                current_node->childs[i]->port_even = -1;
                for(int j = 0; j < 4; j++)
                    current_node->childs[i]->childs[j] = NULL;
            }
            
            current_node->childs[i]->type = M_NODE;
            current_node->childs[i]->port_odd = port;
        }
    }
}

// Constructing an advanced trie-tree to lookup according to `forward_file`
void create_tree_advance(const char* forward_file){
    //fprintf(stderr,"TODO:%s",__func__);
    //init
    destroy_tree_adv(root_adv);
    assert(!root_adv);
    root_adv = (node_adv_t *)malloc(sizeof(node_adv_t));
    root_adv->type = I_NODE;
    root_adv->port_odd = -1;
    root_adv->port_even = -1;
    for(int i = 0; i < 4; i++)
        root_adv->childs[i] = NULL;
    
    //establish tree
    FILE* fp = fopen(forward_file, "r");
	  struct st* sts = (struct st*)malloc(TRAIN_SIZE * sizeof(struct st));
	  for (int i = 0; i < TRAIN_SIZE; i++) {
        char ip[15];
		    int mask;
		    int port;
		    fscanf(fp, "%s %d %d\n", ip, &mask, &port);
		    strcpy(sts[i].ip, ip);
		    sts[i].mask = mask;
		    sts[i].port = port;
	  }
	  fclose(fp);
    
    for(int i = 0; i < TRAIN_SIZE; i++){
        uint32_t ip3, ip2, ip1, ip0, ip;
        sscanf(sts[i].ip, "%d.%d.%d.%d", &ip3, &ip2, &ip1, &ip0);
        ip = (ip3 << 24) | (ip2 << 16) | (ip1 << 8) | ip0;
        retrieve_this_entry_adv(ip, sts[i].mask, sts[i].port);
    }

    direct_pt = (struct dpt_info *)malloc(sizeof(struct dpt_info) * NUM_DIRECT);
    for(int i = 0; i < NUM_DIRECT; i++){
        direct_pt[i].ptr = NULL;
        direct_pt[i].history_port = -1;
    }
    for(uint32_t i = 0; i < NUM_DIRECT; i++){
        int checked_bit = 0;
        node_adv_t *cur_node = root_adv;
        while(1){
            if(checked_bit > BITS_DIRECT-2) break;
            if(cur_node->type == M_NODE){
                direct_pt[i].history_port = cur_node->port_odd;
                if(cur_node->port_even != -1) direct_pt[i].history_port = cur_node->port_even;
            }
            uint32_t this_2_bits = (i >> (BITS_DIRECT-checked_bit-2)) & 3LU;
            checked_bit += 2;
            
            cur_node = cur_node->childs[this_2_bits];
            if(!cur_node) break;
        }
        direct_pt[i].ptr = cur_node;
    }
    
    free(sts);
}

int ip_prefix_cmp_adv(uint32_t tip){
    int checked_bit = 0;
    uint32_t direct_pt_idx = tip >> (32-BITS_DIRECT);
    node_adv_t *cur_node = direct_pt[direct_pt_idx].ptr;
    int res = direct_pt[direct_pt_idx].history_port;
    if(!cur_node) return res;
    tip = tip << BITS_DIRECT;
    while(1){
        if(cur_node->type == M_NODE){
            res = cur_node->port_odd;
            if(cur_node->port_even != -1) res = cur_node->port_even;
        }
        uint32_t this_2_bits = (tip >> (30-checked_bit)) & 3LU;
        checked_bit += 2;
        
        cur_node = cur_node->childs[this_2_bits];
        if(!cur_node) break;
    }
    
    return res;
}

// Look up the ports of ip in file `ip_to_lookup.txt` using the advanced tree input is read from `read_test_data` func 
int *lookup_tree_advance(uint32_t* ip_vec){
    //fprintf(stderr,"TODO:%s",__func__);
    int *res_vec = (int *)malloc(TEST_SIZE * sizeof(int));
    
    for(int i = 0; i < TEST_SIZE; i++){
        //lookup
        res_vec[i] = ip_prefix_cmp_adv(ip_vec[i]);
    }
    
    return res_vec;
}





