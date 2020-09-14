
#ifndef FLOW_TREE_H
#define FLOW_TREE_H
#ifdef __cplusplus
extern "C" {
#endif

#include <libconfig.h>
#include <time.h>
#include <sys/time.h>
#include "uthash.h"
#include "utarray.h"
#include "util.h"
#include "flow.h"
#include "tree_node.h"
#include "flow_tree_hmap.h"
#include <stdlib.h>
#include "packet_bin.h"
#include <string.h>
#include "ft_queue.h"
typedef enum {
  BULK_AND_STACK, BULK_ONLY, STACK_ONLY, DEFAULT_MODE
}ALLOC_MODE; 
  
  
/* Contains configuration of a flow_tree library instance */
typedef struct flow_tree_config_t {
  /*pointer to pointer to hashmap of tree_nodes */
  tree_node *TREE;
  /*pointer to the root of the tree */
  tree_node *root;
  tree_node *node_buffers;
  uint32_t *flow_keys;
  ft_stack * node_stack; 
  ALLOC_MODE allocation_mode; 
  MODE mode;
  unsigned int seed; 
  uint32_t site_id;
  uint32_t granularity;
  uint64_t mem;
  uint64_t mem_exceeded;
  uint64_t max_threshold; 
  uint64_t hash_count;
  uint64_t tree_add;
  uint64_t tree_delete;
  uint64_t mem_max;
  uint64_t timestamp;
  double memory_threshold;
  uint64_t mem_threshold;
  uint64_t n_reclaim;
  uint64_t n_print;
  uint64_t n;
  double time;
  uint32_t time_start;
  double time_next;
  double time_int;
  void *gen_purpose_buffer;
  char *data_path;
  char *out_path;
  char *pkt_file;
  char *pkt_file_full;
  char *out_file_full;
  char *tree_file1buff;
  char *tree_file2buff;
  char *result_file1;
  char *result_file2;
  UT_icd flowkey_icd;
  FILE *pkt_file_fp;
  FILE *stat_file;
  FILE *log_file;
  int written_to_disk; 
} ft_config_t;


  //  void read_tree_from_bin_file(char *tree_file, ft_config_t *conf);
  // void output_flow_tree_bin(char *output_file_name, ft_config_t *conf, flow_tree_meta * meta); 
void init_ft_config(ft_config_t *conf, MODE m);

ft_config_t *create_ft_config();

tree_node *add_packet(char **pkt_str, ft_config_t *conf);

ft_config_t *process_flow_file(char *config_file);

void process_packets(ft_config_t *conf);

uint64_t compute_total_threshold(tree_node **TREE, UT_array *COUNT_LEAF, UT_array *COUNT_INTERIOR);

void compress_to_target(ft_config_t *conf, uint64_t count);
void compress_to_target_fix_counters(ft_config_t *conf, uint64_t count, PROTO proto, COUNTMODE countmode);

uint64_t compute_threshold(tree_node **TREE, UT_array *COUNT_LEAF, UT_array *COUNT_INTERIOR);

int sort_fun(const void *a, const void *b);

void reclaim(ft_config_t *conf);

void do_reclaim(uint64_t threshold, uint64_t threshold_total, ft_config_t *conf);
void do_reclaim_fix_counters(uint64_t threshold, uint64_t threshold_total, ft_config_t *conf, PROTO proto, COUNTMODE countmode);
void print_count(ft_config_t *conf);

void construct_paths(ft_config_t *conf);
  void compress_precisely_to_target(ft_config_t *conf, uint64_t count);
ft_config_t *merge_multiple_trees(UT_array *list_trees, MODE m);
ft_config_t *diff_multiple_trees(UT_array *list_trees, MODE m);
ft_config_t *merge_multiple_trees_with_growth_factor(UT_array *list_trees, MODE m) ;
/*iterates in all nodes of the tree and frees the tree_node_stats member struct to save memory */
/*call this function after you called compute_cur_count and you don't need the count_interior and count_leaf values */
void clean_up_tree(ft_config_t *conf);
  void shallow_copy_tree(ft_config_t *conf_dst, ft_config_t *conf_src);
  int allocate_memory_tree(ft_config_t *conf);
  void add_packet_bin_unlim(packet_bin *packet, ft_config_t *conf);
/* Adds a node to a parent, the tree instance should be passed by the caller */
/* Adds a node to the list of a parent's children. It will check for overlap with the parent's curr
ent children, if the node contains a child, the child will be added to the node's children and removed from current parent */
inline void add_node_to_parent(tree_node *parent, tree_node *node, tree_node **TREE, MODE m) {

    UT_array *psons = parent->children;
    UT_array *newsons = parent->children_bkp;
    int i = 0;
    tree_node **p = NULL;
    for (p = (tree_node **) utarray_front(psons); p != NULL; p = (tree_node **) utarray_next(psons, p)) {
        tree_node *son = *p;
        if (!flowkey_equals(node->flow_key, son->flow_key, m)) {
            if (check_include_flow_key(node->flow_key, son->flow_key, m)) {            
                if (update_parent(son, node, parent, m)) {
                    log_fatal("updating parent failed\n");
                    exit(-1);
                }
            } else {
                utarray_push_back(newsons, p);
            }
        }
        i++;
    }
    utarray_push_back(newsons, &node);
    parent->children = newsons;
    parent->children_bkp = psons;
    utarray_clear(psons);
    //utarray_free(psons);
    //DO_DEBUG(5,"add_node_to_parent: NEW total number of children in the parent is %d\n",utarray_len(psons));

}

/* Find the longest prefix matching parent of a given node in the TREE */
  tree_node *find_parents(tree_node *node, tree_node **TREE, MODE m);
  inline tree_node *add_tree_node_to_tree(tree_node *node , ft_config_t *conf){
{
    tree_node **TREE = &conf->TREE;
    MODE m = conf->mode;
    add_node_hmap((tree_node **) TREE, node, m);   
    conf->mem++;
    conf->tree_add++;
    tree_node *parent = NULL;
    parent = find_parents(node, TREE, m);
    add_node_to_parent(parent, node, TREE, m);
    node->parent = parent;
    return node;
}
 }
  inline tree_node *add_tree_node_from_stack(uint32_t *f, int add, uint64_t counters[], int counter_size,  ft_config_t *conf){
    MODE m = conf->mode;
    tree_node *node = NULL;
    void *void_node = (void *)node;
    stack_pop(conf->node_stack, &void_node);
    node = (tree_node *)void_node;
    node->parent = NULL; 
    int i;
    for(i = 0 ; i<DIM ; i++ )
	{
	  node->flow_key[i]=f[i];
	  node->flow_key[i+DIM]=f[i+DIM];
	}
    node->total_stat = node->comp_pop = 0 ;
    uint64_t cntrs[6]={0,0,0,0,0,0};
    COPY_COMP_COUNTERS(node->comp_counters, cntrs, counter_size); 
    if (add == 0) {      
      ADD_COMP_COUNTERS(node->comp_counters, counters, counter_size);  
    }
    return add_tree_node_to_tree(node, conf);
  }
/* creats a tree_node from a flow, and counters then adds it to the tree */
inline tree_node *add_tree_node(uint32_t *f, int add, uint64_t counters[], int counter_size,  ft_config_t *conf) {
  MODE m = conf->mode; 
  tree_node *node  = create_tree_node_from_flow(f, m);
    if (add == 0) {
      ADD_COMP_COUNTERS(node->comp_counters, counters, counter_size);  
    }
    return add_tree_node_to_tree(node, conf); 
}
inline int delete_node_from_tree(tree_node *node, ft_config_t *conf){
    tree_node **TREE = &conf->TREE;
    tree_node *parent = NULL;
    MODE m = conf->mode;
    //DO_DEBUG(5, "delete_node:deleting \n");
    parent = node->parent;
    conf->tree_delete++;
    if (parent) {
      ADD_COMP_COUNTERS(parent->comp_counters, node->comp_counters, 6); 
        remove_from_children(node, parent, m);
        if (update_parent_simple(node, parent)) {
            log_warn("updating parent simple failed\n");
        };
    }    
   conf->mem--;
   return 0 ; 
}
  inline int delete_node_no_free(tree_node *node, ft_config_t *conf){
    stack_push(conf->node_stack, (void *)node);
    delete_node_from_tree(node, conf);
    reset_node_stats(node);
    utarray_clear(node->children);
    utarray_clear(node->children_bkp);
    tree_node **TREE  = &conf->TREE; 
    remove_node_hmap(TREE, node);
    return 0 ; 
  }
  
/* Deletes a node from TREE, removes it from the parent, takes care of node's children and frees the resources occupied by the node*/
inline int delete_node(tree_node *node, ft_config_t *conf) {
    tree_node **TREE = &conf->TREE;
    delete_node_from_tree(node, conf);
    free_node_hmap((tree_node **) TREE, node);
    return 0;
}
  
  void read_into_counter(char ** packet,uint32_t *counter);
/* Not implemented yet */
int sort_tree_node(tree_node *node1, tree_node *node2);

/* Creates a root node and initializes a TREE */
void add_root(ft_config_t *conf);

/* Calculates a the total value for each node */
void compute_cur_count(tree_node **TREE, UT_array *COUNT_LEAF, UT_array *COUNT_INTERIOR, MODE m);
void compute_cur_count_fix_counters(tree_node **TREE, UT_array *COUNT_LEAF, UT_array *COUNT_INTERIOR, MODE m, PROTO proto, COUNTMODE countmode);
/* Given two already initialized trees, performs diff operation. Updates tree1 */
void diff_trees(ft_config_t *conf1, ft_config_t *conf2);
void diff_trees_stats(ft_config_t *conf1, ft_config_t *conf2);

/* Given two already initialized trees, performs merge operation. Updates tree1 */
void merge_trees(ft_config_t *conf_flow1, ft_config_t *conf_flow2);

ft_config_t *clone_tree(ft_config_t *conf);

tree_node *add_packet_unlimited(char **pkt_str, ft_config_t *conf);

void add_packet_bin(packet_bin *packet, ft_config_t *conf) ;
  ft_config_t *clone_bulk_tree(ft_config_t *tree_to_clone);
  void free_multiple_trees(UT_array *list_trees);
  int convert_tree_modes(ft_config_t *conf_dest, ft_config_t * conf_src);   

int free_ft_config(ft_config_t *ft);
void fix_root_ptr(ft_config_t *tree_to_fix);

#ifdef __cplusplus
}
#endif
#endif
