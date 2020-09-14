#ifndef TREE_NODE_H
#define TREE_NODE_H
#ifdef __cplusplus
extern "C" {
#endif
#include "uthash.h"
#include "utarray.h"
#include "util.h"
#include "flow.h"

#define COPY_COMP_COUNTERS(a,b,c) do{		\
    for(int i = 0 ; i < c ; i++){		\
      a[i] = b[i];				\
    }						\
  }while(0);
#define ADD_COMP_COUNTERS(a,b,c) do{		\
    for(int i = 0 ; i < c ; i++){		\
      a[i] += b[i];				\
    }						\
  }while(0);
#define GET_TOTAL_COMP(a) (a->comp_counters[0] + a->comp_counters[3])

#define GET_TOTAL_COMP_PROTO_COUNTMODE(a,proto,countmode) ((proto == 2) ? (a->comp_counters[countmode] + a->comp_counters[countmode+3]) : a->comp_counters[proto*3+countmode])

struct tree_node;
typedef struct tree_node_stats{
  uint64_t pop;
  uint64_t cson_stat;
  uint64_t done_stat;
  uint64_t cur_count_stat;
  uint64_t count_leaf;
  uint64_t count_interior;

} tree_node_stats;

typedef struct tree_node_flags {
    unsigned int leaf : 1;
    unsigned int visited : 1;
    unsigned int flag : 1; 
}tree_node_flags; 
  
typedef struct tree_node {
  uint32_t *flow_key;
  uint64_t comp_pop;
  uint64_t total_stat;
  uint64_t comp_counters[6]; 
  tree_node_flags flags; 
  struct tree_node *parent;
  tree_node_stats *stats; 
  UT_array *children;
  UT_array *children_bkp; 
  UT_hash_handle hh;
} tree_node; 

extern UT_icd flowkey_icd;

/* checks if a node is a subset of another node from feature hierarchy perspective */
  int check_include(tree_node *node, tree_node * subnode, MODE m);

/* Takes an array of pointers to strings and array of prefix lengths and creates a tree_node */
  tree_node *create_tree_node(char *packet[], int prefixes[], MODE m);

  tree_node * create_tree_node_from_flow(uint32_t *flow_key, MODE m);
  tree_node * create_tree_node_from_key(uint32_t *flow_key, MODE m);
  //  void create_tree_node_from_flow_bulk(uint32_t *flow_key, MODE m,  tree_node *buffer_handle, uint32_t * flow_keys_buffer_handle);
  int init_node(tree_node * node);
/* checks if a tree_node is a leaf node. It calls is_leaf_flow */ 
  int is_leaf(tree_node *node, MODE m);

  inline void destroy_children(tree_node *node){
    if(node->children!=NULL)
      utarray_free(node->children);    
    if(node->children_bkp!=NULL)
      utarray_free(node->children_bkp);	    
    if(node->stats!=NULL)
      free(node->stats);	
    node->children = NULL;
    node->children_bkp = NULL;
    node->stats = NULL;
  }
  /* Compares the flow_key value of two tree_nodes, return 1 if they have same key */
  int node_equals(tree_node *node1, tree_node *node2, MODE m);

/* Prints the string version of a node to standard error and the log file */
  void print_node(tree_node *node, MODE m);

/* Searches for the node key in the list of a parent's children, if found, it will remove the key f\
rom the list */
  int remove_from_children(tree_node *node, tree_node *parent, MODE m);

 inline void add_to_children(tree_node *node, tree_node *parent){
      utarray_push_back( parent->children, &node);
  }

/* Searches for the node key in the list of parent's children and also if it is in the Tree. This f\
unctionality will be replaced by check_node_in_sons_simple returns 1 if found, other wise 0 */
 inline int check_node_in_sons(tree_node *node, tree_node *parent, MODE m){
  UT_array *children =	parent->children;
  tree_node **p = NULL;
  for(p=(tree_node **)utarray_front(children); p!=NULL; p=(tree_node **)utarray_next(children,p)){
    tree_node *son=*p;
    if(flowkey_equals(son->flow_key, node->flow_key, m )){
      return 1;
    }
  }
  return 0;

  }

  int check_node_in_sons_simple(tree_node *node, tree_node *parent, MODE m);

/* Converts a node into string and puts it in the buffer */
  size_t node_to_string_compact(tree_node *node, char *buff, MODE m);

/* Converts a node, its comp_pop, total_value and all of its children to string representation and puts the string into the \
buff, buffer should be sufficiently large, since a node might have many children */
  size_t node_to_string_full(tree_node *node, char *buff, size_t buff_size,tree_node **TREE, MODE m);

  size_t node_to_string_compact(tree_node *node, char *buff, MODE m);
/* resets the total stat value and other transient values of a node to 0 */
void reset_node_stats(tree_node *node);

/* Removes a node from an old parent and adds it to the new_parent */
int update_parent(tree_node *node, tree_node *new_parent, tree_node *old_parent, MODE m);

int update_parent_simple(tree_node *node, tree_node *parent);
#ifdef __cplusplus
}
#endif
#endif
