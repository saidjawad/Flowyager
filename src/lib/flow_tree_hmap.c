#include "flow_tree_hmap.h"

extern tree_node * get_flow_hmap_(const tree_node **tree, const uint32_t *flow_key, MODE m);

void add_node_hmap(tree_node **tree, tree_node *node, MODE m){
  
  HASH_ADD_KEYPTR(hh,*tree,node->flow_key,MODE_SIZES[m] ,node);

  //  tree_node *n1    = get_flow_hmap_(tree, node->flow_key, m);
  //printf("\n\n\n\n\n\n\nprinting the recently added node\n");
  //print_flow_key(n1->flow_key,m);
}

int node_in_hmap(tree_node **tree, tree_node *node, MODE m){
  tree_node *p=NULL;
  HASH_FIND(hh,*tree,node->flow_key,MODE_SIZES[m],p);
  if(p){
    return 1;
  }
  else{
    return 0;
  }
}

int flow_in_hmap(const tree_node **tree,const uint32_t *flow_key, MODE m){
  tree_node *p=NULL;
  HASH_FIND(hh,*tree,flow_key,MODE_SIZES[m] ,p);
  if(p){
    return 1;
  }
  else{
    return 0;
  }
}

void get_flow_hmap(const tree_node **tree, tree_node **node, const uint32_t *flow_key, MODE m ){
  HASH_FIND(hh,*tree,flow_key,MODE_SIZES[m],*node);
 }

void remove_node_hmap(tree_node **tree, tree_node *node){
 HASH_DEL(*tree, node); 
}
void free_node_hmap(tree_node **tree, tree_node *node){
  //DO_DEBUG(5,"free_node_hmap_deleting node\n");

  uint32_t *key = node->flow_key;
  destroy_children(node); 
  HASH_DEL(*tree, node);
  free(key);
  free(node);
}

int remove_node_by_flow_hmap(tree_node **tree, uint32_t *flow_key, MODE m){
  tree_node * node = NULL;
  node = get_flow_hmap_((const tree_node **)tree, flow_key , m);
  if(node){
   remove_node_hmap(tree,node);
   return 1; 
  }
  return 0; 
}

int free_node_by_flow_hmap(tree_node **tree, uint32_t *flow_key, MODE m){
  tree_node * node = NULL;
  node = get_flow_hmap_((const tree_node **)tree, flow_key ,m);
  if(node){
   free_node_hmap(tree,node);
   return 1;
  }
  return 0;
}

void clear_hmap(tree_node *tree){
  HASH_CLEAR(hh,tree);
}

void free_hmap(tree_node **tree){
  tree_node *t = *tree; 
  tree_node *node, *tmp;
  HASH_ITER(hh,t,node,tmp){
    HASH_DEL(t,node);
    destroy_children(node);
    uint32_t *node_key = node->flow_key;
    free(node_key);
    free(node);
  }
}
void free_hmap_only(tree_node **tree){
  tree_node *node, *tmp;
  HASH_ITER(hh,*tree,node,tmp){
    destroy_children(node); 
    HASH_DEL(*tree,node);
  }
}
/*tree_node * replace_node_hmap(tree_node **tree, tree_node *oldnode, tree_node *newnode){
  
  HASH_REPLACE(hh,*tree,flow_key,FLOW_KEY_SIZE*sizeof(uint32_t) ,newnode,oldnode);
  return oldnode;
}

tree_node * replace_node_by_flow_hmap(tree_node **tree, tree_node *newnode, uint32_t *flow_key){
  tree_node *node ;

  node = get_flow_hmap_((const tree_node **)tree, flow_key);
  if(node){
    return replace_node_hmap(tree,node,newnode);
  }
  return NULL;
}
*/
uint32_t count_hmap(tree_node ** tree){
  unsigned int num_items ;
  num_items = HASH_COUNT(*tree);
  return (uint32_t) num_items;

}
