#ifndef FLOW_TREE_QUERY_H
#define FLOW_TREE_QUERY_H
#ifdef __cplusplus
extern "C" {
#endif
#include "flow_tree.h"
#include "ft_queue.h"


void process_query(char **flow_str, ft_config_t *TREE_config, MODE m, int k, char *buff, uint32_t buff_size, uint64_t thresh);
void process_query_top_k(char **flow_str, ft_config_t *TREE_config, MODE m, int k, char *buff, uint32_t buff_size, uint64_t thresh);
void process_query_top_k_any(char **flow_str, ft_config_t *TREE_config, MODE m, int k, char *buff, uint32_t buff_size, uint64_t thresh);

void BFS_top_k(tree_node* start_node , char* buff, uint32_t buff_size, tree_node **TREE , MODE m, uint32_t k, uint64_t thresh);
void BFS_top_k_any(char *flow_str_any_to_search, tree_node *start_node, char *buff, uint32_t buff_size, tree_node **TREE, MODE m, uint32_t k, uint64_t thresh) ;
uint64_t BFS_pop_any(char *flow_str_any_to_search, tree_node *start_node, tree_node **TREE, MODE m, uint32_t k, uint64_t thresh) ;

ft_config_t* create_tree_out_of_nodes(char* search_str, ft_config_t* src_config, MODE mode) ;
int create_inclusive_tree(char* search_str, ft_config_t *dst_config, ft_config_t *src_config);

#ifdef __cplusplus
}
#endif
#endif
