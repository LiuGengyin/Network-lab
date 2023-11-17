#ifndef __TREE_H__
#define __TREE_H__

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <math.h>

// do not change it
#define TEST_SIZE 100000

#define TRAIN_SIZE 697882 
#define I_NODE 0 // internal node
#define M_NODE 1 // match node
#define LEFT 0
#define RIGHT 1
#define BITS_DIRECT 16
#define NUM_DIRECT pow(2, BITS_DIRECT)

#define MASK(x,y) (((x) & 0x000000ff) << (y))
typedef struct node{
    bool type; //I_NODE or M_NODE
    int port;
    struct node* lchild;
    struct node* rchild;
}node_t;

extern node_t *root;

//advanced
typedef struct node_adv{
    bool type;
    int port_odd;
    int port_even; //will have higher priority than port_odd
    struct node_adv *childs[4];
}node_adv_t;

extern node_adv_t *root_adv;

void create_tree(const char*);
int *lookup_tree(uint32_t *);
void create_tree_advance(const char*);
int *lookup_tree_advance(uint32_t *);

uint32_t* read_test_data(const char* lookup_file);

#endif
