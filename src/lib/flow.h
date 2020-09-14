#ifndef FLOW_HH_
#define FLOW_HH_
#ifdef __cplusplus
extern "C" {
#endif
#include <string.h>
#include "util.h"
#include "utarray.h"
#include "packet_bin.h"

#define LIST_ITER(t, itm, list) for(itm = (t **)utarray_front(list); itm != NULL; itm = (t **)utarray_next(list,itm))
extern void (* MODE_CONVERSION_TABLE[11][11])(uint32_t *, uint32_t *);
  void convert_2D_to_1D_first_element(uint32_t *dest_flow_key, uint32_t *src_flow_key);
  void convert_2D_to_1D_second_element(uint32_t *dest_flow_key, uint32_t *src_flow_key);
  void convert_FULL_SIDI(uint32_t *dest_flow_key, uint32_t *src_flow_key);
  void convert_FULL_SPDP(uint32_t *dest_flow_key, uint32_t *src_flow_key);
  void convert_FULL_SISP(uint32_t *dest_flow_key, uint32_t *src_flow_key);
  void convert_FULL_SIDP(uint32_t *dest_flow_key, uint32_t *src_flow_key);
  void convert_FULL_DISP(uint32_t *dest_flow_key, uint32_t *src_flow_key);
  void convert_FULL_DIDP(uint32_t *dest_flow_key, uint32_t *src_flow_key);
  void convert_FULL_SI(uint32_t *dest_flow_key, uint32_t *src_flow_key);
  void convert_FULL_DI(uint32_t *dest_flow_key, uint32_t *src_flow_key);
  void convert_FULL_SP(uint32_t *dest_flow_key, uint32_t *src_flow_key);
  void convert_FULL_DP(uint32_t *dest_flow_key, uint32_t *src_flow_key);
  
  int create_flow_from_tree_file(char **flow, uint32_t *flow_key, MODE m);

/*  parent_flow. Given a flow, it constructs a direct parent and fills the paren
t_flow. If the parent is going to be root, it returns 1, the caller must call the root flow later to
 get the root flow */
  int parent_flow( uint32_t *node, uint32_t *parent_flow, MODE m);

/* Prints a flow_key like print_node */
  void print_flow_key(uint32_t *flow_key, MODE m);

/* Creates a flow which has the same flow_key and flow values as the root of the tree */
  void root_flow( uint32_t *f, MODE m);
  
 /* Takes two flow_keys and check whether a flow_key is a subflow another one. Returns 1 if it is the subflow */
 inline int check_include_flow_key(uint32_t *node_key, uint32_t *subnode_key, MODE m){
   mask_idx idxs = MASK_IDXs[m];
   int i;
   for(i = 0 ; i < DIM; i++){
     int ip_or_port = idxs.idx[i];
     const uint32_t *mask_list = MASK_TABLE[ip_or_port];
     if(!((*(node_key +i)==(*(subnode_key +i) & mask_list[(*(node_key+i+DIM))])) && (*(node_key +i+DIM)<=*(subnode_key + i + DIM)) ))
       return 0 ;
   }
   return 1;
 }


/* checks if a flow is leaf node */
  inline int is_leaf_flow(uint32_t *flow_key , MODE m){
    int i;
    const uint32_t *max_mask_vals = MAX_PREFIXES[m].prefs;
    for(i = 0 ; i < DIM ; i++){
        if(flow_key[i+DIM]!=*(max_mask_vals + i))
            return 0 ;
    }
    return 1;
}

/* Compares two flow_keys, returns 1 if they are equal */
  inline int flowkey_equals(uint32_t *node1, uint32_t *node2, MODE m){
  int index;
  for(index = 0 ; index < (DIM*2) ; index++){
    if(*(node1+index)!=*(node2+index))
      return 0;
  }
  return 1;
}
  
/* Takes an array of pointers to strings and array of prefix lengths and creates a flow struct (do n
ot use directly, use CREATE_FLOW macro) */
  
  inline int create_flow_from_packet(char *packet[], int prefixes[], uint32_t *flow_key, MODE m) {
    const mask_idx idxs = MASK_IDXs[m];
    const mask_idx pkt_idx = PACKET_IDXs[m];
    int sizes = idxs.size;
    int i;
    for (i = 0; i < sizes; i++) {
      int ip_or_port = idxs.idx[i];
      const uint32_t *mask_list = MASK_TABLE[ip_or_port];
      if (!ip_or_port) {
	flow_key[i] = (ip4_str_int_le(packet[pkt_idx.idx[i]]) & mask_list[prefixes[i]]);
      } else {
	flow_key[i] = (str_to_le_int32(packet[pkt_idx.idx[i]]) & mask_list[prefixes[i]]);
      }
      flow_key[i + sizes] = (uint32_t) prefixes[i];

    }

  }

inline int create_flow_from_packet_bin(packet_bin *packet, int prefixes[], uint32_t *flow_key, MODE m) {
    const mask_idx idxs = MASK_IDXs[m];
    const mask_idx pkt_idx = PACKET_IDXs[m];
    int sizes = idxs.size;
    int i;
    for (i = 0; i < sizes; i++) {
        int ip_or_port = idxs.idx[i];
        const uint32_t *mask_list = MASK_TABLE[ip_or_port];
        flow_key[i] = ((packet->values[pkt_idx.idx[i] - 1]) & mask_list[prefixes[i]]);
        flow_key[i + sizes] = (uint32_t) prefixes[i];
    }
    return 0;
}

#ifdef __cplusplus
}
#endif
#endif
