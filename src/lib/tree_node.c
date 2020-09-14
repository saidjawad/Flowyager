#include "tree_node.h"
UT_icd flowkey_icd = {sizeof(tree_node *),NULL,NULL,NULL};
extern inline int check_node_in_sons(tree_node *node, tree_node *parent, MODE m);
extern inline void destroy_children(tree_node *node);
int check_include(tree_node *node, tree_node *subnode, MODE m){
  uint32_t *node_flow = node->flow_key;
  uint32_t *subnode_flow = subnode->flow_key;
  return check_include_flow_key(node_flow,subnode_flow, m);
}

tree_node *create_tree_node(char *packet[], int prefixes[], MODE m){
  uint32_t flow_key[DIM*2];
  memset(flow_key,0,MODE_SIZES[m]);
  create_flow_from_packet(packet,prefixes,flow_key, m );
  return create_tree_node_from_flow(flow_key, m);
}

tree_node * create_tree_node_from_flow(uint32_t *flow_key, MODE m){
  tree_node *node = calloc(1,sizeof(tree_node));
  uint32_t *f_key = (uint32_t *)calloc(1,DIM*2*sizeof(uint32_t));
  node->flow_key = f_key;
  int i;
  for(i = 0 ; i<DIM ; i++ )
   {
    node->flow_key[i]=flow_key[i];
    node->flow_key[i+DIM]=flow_key[i+DIM];
   }
  node->total_stat = 0;
  node->comp_pop=0;
  UT_array *children;
  utarray_new(children,&flowkey_icd);
  node->children = children;
  UT_array *children_bkp;
  utarray_new(children_bkp,&flowkey_icd);
  node->children_bkp = children_bkp;
  return node;
}

  int init_node(tree_node * node){
    if(node){
      node->total_stat = 0;
      node->comp_pop=0;
      memset(node->comp_counters, 0 , 6 * sizeof(uint64_t)); 
      UT_array *children;
      utarray_new(children,&flowkey_icd);
      node->children = children;
      UT_array *children_bkp;
      utarray_new(children_bkp,&flowkey_icd);
      node->children_bkp = children_bkp;
      return 0;
    }
    return -1;
}

tree_node * create_tree_node_from_key(uint32_t *flow_key, MODE m){

  return create_tree_node_from_flow(flow_key, m);
}
int is_leaf(tree_node *node, MODE m){
  return is_leaf_flow(node->flow_key,m);
}

extern inline void add_to_children(tree_node *node, tree_node *parent);

int update_parent(tree_node *node, tree_node *new_parent, tree_node *old_parent, MODE m){
     node->parent = new_parent;
     if(!check_node_in_sons(node,new_parent,m)){
        /// DO_DEBUG(5,"update_parent: adding node to new parent");
	    add_to_children(node,new_parent);
      }
     //DO_DEBUG(5,"update_parent: ->remove_from_children\n");
      return 0;
}

int update_parent_simple(tree_node *node, tree_node *parent){
  UT_array *children = node->children;
  tree_node **p = NULL;
  for(p=(tree_node **)utarray_front(children); p!=NULL; p=( tree_node **)utarray_next(children,p)){
    tree_node *son = *p;
    if(!son){
      // DO_DEBUG(5,"update_parent_simple: null node detected\n");
      return 1;
    }
    add_to_children(son,parent);
    son->parent=parent;
   }
  return 0;
}

int check_node_in_sons_simple(tree_node *node, tree_node *parent, MODE m){

  UT_array *children =  parent->children;
  tree_node **p = NULL;
  for(p=(tree_node **)utarray_front(children); p!=NULL; p=(tree_node **)utarray_next(children,p)){
    if(flowkey_equals(node->flow_key, (*p)->flow_key, m)){
      return 1;
      }
  }
    return 0;
 }

int remove_from_children(tree_node *node, tree_node *parent,MODE m){
  UT_array *children = parent->children;
  tree_node **p = NULL;
  //DO_DEBUG(5,"remove_from_children: children_length: before_removal %d\n",utarray_len(children));            
  for(p=(tree_node **)utarray_front(children); p!=NULL; p=(tree_node **)utarray_next(children,p)){
    tree_node *curr_node = *p;
    if(flowkey_equals(curr_node->flow_key, node->flow_key, m)){
        unsigned int id = utarray_eltidx(children,p);
        utarray_erase(children,id,1);
        return 0;
    }
  }
    return 1;
}

int node_equals(tree_node *node1, tree_node *node2, MODE m){
  int index  ;
  for(index = 0 ; index < DIM*2; index++){
    if(node1->flow_key[index]!=node2->flow_key[index])
      return 0;
  }
  return 1 ;
}

void print_node( tree_node *node, MODE m ){

}


size_t node_to_string_full(tree_node *node, char *buff, size_t buff_size,tree_node **TREE, MODE m){
  size_t buff_used;
  buff_used = node_to_string_compact(node, buff,m);
  char pop_values[256];
  sprintf(pop_values,"-%lu-%lu-%lu-%lu-%lu-%lu-%lu-",
	  node->comp_counters[0],node->comp_counters[1],node->comp_counters[2],
	  node->comp_counters[3],node->comp_counters[4],node->comp_counters[5] ,node->total_stat);
  strcat(buff,pop_values);
  char parent[128];
  if(node->parent){
    buff_used += node_to_string_compact(node->parent, parent,m);
    strcat(buff, parent);
    strcat(buff,":");
  }
  strcat(buff,"-");
  return buff_used;
}


size_t node_to_string_compact(tree_node *node, char *buff, MODE m){
  mask_idx idxs = MASK_IDXs[m];
  size_t buff_used;
  size_t str_size;
  uint32_t *flow_key;
  flow_key = node->flow_key;
  char str[INET_ADDRSTRLEN];
  char str2[INET_ADDRSTRLEN];
  //  char *str;
  if(!idxs.idx[0])
    int_le_ip4_str(flow_key[0],str);
  else
    int_le_to_str(flow_key[0],str);
  str_size = strlen(str);
  char str_buff[str_size+1];
  strcpy(str_buff, str);
  if(DIM==4){
      int_le_ip4_str(flow_key[1],str2);
      buff_used = sprintf(buff,"%s|%u,%s|%u,%u|%u,%u|%u",str_buff,flow_key[DIM],str2,flow_key[DIM+1],flow_key[2],flow_key[DIM+2],flow_key[3],flow_key[DIM+3]);

  }else if(DIM==2){
    if(!idxs.idx[1]){
      int_le_ip4_str(flow_key[1],str2);
      buff_used = sprintf(buff,"%s|%u,%s|%u", str_buff,flow_key[DIM],str2,flow_key[DIM+1]);
    }
    else{
      int_le_to_str(flow_key[1],str2);
      buff_used = sprintf(buff,"%s|%u,%s|%u",str_buff,flow_key[DIM],str2,flow_key[DIM+1]);
    }
  }else if(DIM==1){
        buff_used = sprintf(buff,"%s|%u",str_buff,flow_key[DIM]);
  }else{
    printf("invalid dimension: %d- NOT supported yet",DIM);
    exit(-1);
  }
  return buff_used;
  

}
void reset_node_stats(tree_node *node){
  if(node->stats){
    tree_node_stats *stats = node->stats;
    stats->cson_stat=0;
    stats->done_stat=0;

    stats->cur_count_stat=0;
    stats->count_leaf=0;
    stats->count_interior=0;
  }
  node->total_stat=0;
  node->flags.leaf=0;
}
