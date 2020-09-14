#ifndef FLOW_TREE_HMAP_H
#define FLOW_TREE_HMAP_H
#ifdef __cplusplus
extern "C" {
#endif
#include "tree_node.h"
#include "uthash.h"
#include "utarray.h"
/** tree_node **tree should be a pointer to pointer to hashmap **/
/** tree_node *node is a pointer to a tree_node **/
/** uint32_t *flow_key points to first element of the flow_key array **/
/** it is recommended to allocate memory with calloc before initializing a node **/

/* Adds a node to hashmap, use calloc for allocating memory to the node */
  void add_node_hmap(tree_node **tree, tree_node *node, MODE m);

/* checks a node presence, based on the flow_key value stored in the node */
int  node_in_hmap(tree_node **tree, tree_node *node, MODE m);

/* checks a node presence, looks up based the passed flow_key */
int flow_in_hmap(const tree_node **tree, const uint32_t *flow_key, MODE m);

/* Looks up and returns the node based on the flow_key(if not present returns NULL) */
//tree_node * get_flow_hmap_(const tree_node **tree, const uint32_t *flow_key );
inline tree_node * get_flow_hmap_(const tree_node **tree, const uint32_t *flow_key , MODE m){                           
  tree_node * my_node;
  //  printf("get_flow_hmap_ looking for a node\n");
  //print_flow_key((uint32_t *)flow_key,m);
  HASH_FIND(hh,*tree,flow_key,MODE_SIZES[m],my_node);                                   
  if(my_node){                                                                                           
    return my_node;                                                                                      
  }                                                                                                      
  else{                                                                                                  
    return NULL;                                                                                         
  }                                                                                                      
 }    

/* Looks up and initializes the passed node pointer if the passed flow_key presents in the hashmap */
/* before calling the function initialize the node pointer to NULL */
void get_flow_hmap(const tree_node **tree, tree_node **node, const uint32_t *flow_key, MODE m );

/* Removes the node from hashmap it only checks the flow_key field (does not free it)*/
void remove_node_hmap(tree_node **tree, tree_node *node);

/* Removes the node from hashmap, if it is present(look up flow_key), returns 1 if successful */
  int remove_node_by_flow_hmap(tree_node **tree, uint32_t *flow_key, MODE m);

/* Removes the node from hashmap, and frees its memory(look up based on flow_key) returns 1 if successful */
int free_node_by_flow_hmap(tree_node **tree, uint32_t *flow_key, MODE m);

/* Removes the node from hashmap and frees its memory(look up based on flow_key)*/
void free_node_hmap(tree_node **tree, tree_node *node);

/* Removes all the nodes in the hashmap */
void clear_hmap(tree_node *tree);

/* Removes all the nodes from hashmap and frees each of them */ 
void free_hmap(tree_node **tree);
  void free_hmap_only(tree_node **tree);
/* Replaces the old_node with new_node, retuns a pointer to the old_node if successful otherwise NULL*/
//tree_node * replace_node_hmap(tree_node **tree, tree_node *oldnode, tree_node *newnode, MODE m);

/* Replaces the old_node if it can find it based on flow_key returns a pointer to old_node if successful otherwise NULL*/
//tree_node * replace_node_by_flow_hmap(tree_node **tree, tree_node *newnode, uint32_t *flow_key, MODE m);

/* Returns the number of nodes in the hashmap */
uint32_t count_hmap(tree_node ** tree);
#ifdef __cplusplus
}
#endif
#endif
