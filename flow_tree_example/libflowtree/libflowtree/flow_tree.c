#include "flow_tree.h"
typedef __int128 int128_t;

UT_array *sort_tree_nodes(UT_array *list) {
    //TODO sort children
    return list;
}

extern inline void add_node_to_parent(tree_node *parent, tree_node *node, tree_node **TREE, MODE m);
extern inline tree_node *add_tree_node_to_tree(tree_node *node , ft_config_t *conf);
extern inline tree_node *add_tree_node(uint32_t *f, int add, uint64_t counters[], int counter_size,  ft_config_t *conf);
extern inline int delete_node(tree_node *node, ft_config_t *conf);
extern inline int delete_node_from_tree(tree_node *node, ft_config_t *conf);
extern inline int delete_node_no_free(tree_node *node, ft_config_t *conf);
extern inline tree_node *add_tree_node_from_stack(uint32_t *f, int add, uint64_t counters[], int counter_size,  ft_config_t *conf);
ft_config_t *create_ft_config() {
    ft_config_t *ft = NULL;
    ft = calloc(1, sizeof(ft_config_t));
    ft->allocation_mode = DEFAULT_MODE;
    ft->written_to_disk = 1;
    return ft;
}
int free_nodes_in_bulk(ft_config_t *ftree){
  if(ftree->node_buffers==NULL) return -1;
  tree_node *tree_nodes_buff =ftree->node_buffers;
  for(uint32_t j = 0 ; j < ftree->mem_max ; j++){
    tree_node *node = &tree_nodes_buff[j];
    destroy_children(node);
  }
  return 0;
}
int free_nodes_from_stack(ft_config_t * ftree){
  if(ftree->node_stack == NULL) return -1;
  ft_stack *node_stack = ftree->node_stack;
  while(!node_stack->empty){
    void *void_node = NULL;
    stack_pop(node_stack, &void_node);
    tree_node *node = (tree_node *)void_node;
    destroy_children(node);
    free(node->flow_key);
    free(node);
  }

}
int free_ft_config(ft_config_t *ft) {
  switch(ft->allocation_mode){
  case BULK_AND_STACK:
    free_nodes_in_bulk(ft);
    free_hmap_only(&ft->TREE);
    if(ft->node_buffers) free(ft->node_buffers);
    if(ft->flow_keys) free(ft->flow_keys);
    stack_destroy(ft->node_stack);
    break;
  case BULK_ONLY:
    free_nodes_in_bulk(ft);
    free_hmap_only(&ft->TREE);
    if(ft->node_buffers) free(ft->node_buffers);
    if(ft->flow_keys) free(ft->flow_keys);
    break;
  case STACK_ONLY:
    free_hmap(&ft->TREE);
    free_nodes_from_stack(ft);
    stack_destroy(ft->node_stack);
    break;
  default:
    free_hmap(&ft->TREE);
    break;
    }

  ft->TREE = NULL;
  ft->root = NULL;
  if (ft->pkt_file_fp) fclose(ft->pkt_file_fp);
  if (ft->stat_file) fclose(ft->stat_file);
  if (ft->log_file) fclose(ft->log_file);
  free(ft);
  return 0;
}

void add_root(ft_config_t *conf) {
    tree_node *root = NULL;
    MODE m = conf->mode;
    if(conf->allocation_mode == STACK_ONLY || conf->allocation_mode == BULK_AND_STACK){
	void *void_node = (void *)root;
	stack_pop(conf->node_stack, &void_node);
	root = (tree_node *)void_node;
	memset(root->flow_key, 0, MODE_SIZES[m]);
    }else{
      uint32_t flow_key[DIM * 2];
      memset(flow_key, 0, MODE_SIZES[m]);
      root = create_tree_node_from_flow(flow_key, m);
    }
    root->parent = NULL;
    add_node_hmap((tree_node **) &conf->TREE, root, m);
    conf->mem++;
    conf->root = root;
}


tree_node *find_parents(tree_node *node, tree_node **TREE, MODE m) {
    uint32_t parent[DIM * 2];
    uint32_t node_flow[DIM * 2];
    memset(parent, 0, MODE_SIZES[m]);
    memset(node_flow, 0, MODE_SIZES[m]);
    memcpy(node_flow, node->flow_key, MODE_SIZES[m]);
    //log_warn("printing the memcpy result");
    //print_flow_key(node_flow,m);
    uint32_t iteration = 0;
    tree_node *par = NULL;
    while (!par && iteration < 32) {
        //DO_DEBUG(5,"searching for parent\n");
        parent_flow(node_flow, parent, m);
        par = get_flow_hmap_((const tree_node **) TREE, (const uint32_t *) parent, m);
        if (par) {
            return par;
        } else {
            memcpy(node_flow, parent, MODE_SIZES[m]);
            //node_flow = parent;
            par = NULL;
        }
	iteration++;
    }

    return NULL;
}

void compute_cur_count(tree_node **TREE, UT_array *COUNT_LEAF, UT_array *COUNT_INTERIOR, MODE m) {

    int pop = 1;
    tree_node *node, *tmp;
    UT_array *leafs;
    utarray_new(leafs, &flowkey_icd);
    HASH_ITER(hh, *TREE, node, tmp) {
        if (!node->stats) node->stats = calloc(1, sizeof(tree_node_stats));
        reset_node_stats(node);
        tree_node_stats *stats = node->stats;
        //DO_DEBUG(5,"compute_cur_count : iterating searching for leafs\n");
        if (is_leaf(node, m) || utarray_len(node->children) == 0) {
            utarray_push_back(leafs, &node);
            stats->count_leaf = GET_TOTAL_COMP(node);
            //print_flow_key(node->flow_key);
            utarray_push_back(COUNT_LEAF, &node);
            node->flags.leaf = 1;
        } else {
	  stats->cson_stat = utarray_len(node->children);
            utarray_push_back(COUNT_INTERIOR, &node);
        }
    }
    tree_node **flow_key = NULL;
    while (utarray_len(leafs)) {
        flow_key = (tree_node **) utarray_back(leafs);
        pop = 1;
        tree_node *curr_node = *flow_key;
        tree_node *parent = NULL;
        if (!curr_node) {
            log_fatal("found a flow key that is not present in the tree\n");
            //      print_flow_key((*flow_key)->flow_key);
            exit(-1);
        }
        if (curr_node->stats->cson_stat == curr_node->stats->done_stat) {
	  curr_node->total_stat += (GET_TOTAL_COMP(curr_node));
            if (!curr_node->flags.leaf) {
                curr_node->stats->count_interior += curr_node->total_stat;
            }
            parent = curr_node->parent;
            if (parent) {
                parent->total_stat += curr_node->total_stat;
                parent->stats->done_stat++;
                if (parent->stats->done_stat == parent->stats->cson_stat) {
                    utarray_pop_back(leafs);
                    pop = 0;
                    utarray_push_back(leafs, &parent);
                }
            } else {
                //log_trace("compute_cur_count: orphan node\n");
            }
            curr_node->stats->cur_count_stat = curr_node->total_stat;
            if (pop) utarray_pop_back(leafs);
        }
    }

    utarray_free(leafs);
}

void compute_cur_count_fix_counters(tree_node **TREE, UT_array *COUNT_LEAF, UT_array *COUNT_INTERIOR, MODE m, PROTO proto, COUNTMODE countmode) {

    int pop = 1;
    tree_node *node, *tmp;
    UT_array *leafs;
    utarray_new(leafs, &flowkey_icd);
    HASH_ITER(hh, *TREE, node, tmp) {
        if (!node->stats) node->stats = calloc(1, sizeof(tree_node_stats));
        reset_node_stats(node);
        tree_node_stats *stats = node->stats;
        //DO_DEBUG(5,"compute_cur_count : iterating searching for leafs\n");
        if (is_leaf(node, m) || utarray_len(node->children) == 0) {
            utarray_push_back(leafs, &node);
            if (proto == ALL)
                stats->count_leaf = node->comp_counters[countmode] + node->comp_counters[countmode + 3];
            else
                stats->count_leaf = node->comp_counters[proto*3 + countmode];

//            print_flow_key(node->flow_key);
            utarray_push_back(COUNT_LEAF, &node);
            node->flags.leaf = 1;
        } else {
            stats->cson_stat = utarray_len(node->children);
            utarray_push_back(COUNT_INTERIOR, &node);
        }
    }
    tree_node **flow_key = NULL;
    while (utarray_len(leafs)) {
        flow_key = (tree_node **) utarray_back(leafs);
        pop = 1;
        tree_node *curr_node = *flow_key;
        tree_node *parent = NULL;
        if (!curr_node) {
            log_fatal("found a flow key that is not present in the tree\n");
            //      print_flow_key((*flow_key)->flow_key);
            exit(-1);
        }
        if (curr_node->stats->cson_stat == curr_node->stats->done_stat) {
            uint32_t tmp_total_comp = 0;
            if (proto == ALL)
                tmp_total_comp = curr_node->comp_counters[countmode] + curr_node->comp_counters[countmode + 3];
            else
                tmp_total_comp = curr_node->comp_counters[proto*3 + countmode];

            curr_node->total_stat += tmp_total_comp;
            if (!curr_node->flags.leaf) {
                curr_node->stats->count_interior += curr_node->total_stat;
            }
            parent = curr_node->parent;
            if (parent) {
                parent->total_stat += curr_node->total_stat;
                parent->stats->done_stat++;
                if (parent->stats->done_stat == parent->stats->cson_stat) {
                    utarray_pop_back(leafs);
                    pop = 0;
                    utarray_push_back(leafs, &parent);
                }
            } else {
                //log_trace("compute_cur_count: orphan node\n");
            }
            curr_node->stats->cur_count_stat = curr_node->total_stat;
            if (pop) utarray_pop_back(leafs);
        }

    }

    utarray_free(leafs);
}

void calc_thresholds(ft_config_t *conf, uint64_t * thresholds) {
    tree_node **TREE = &conf->TREE;
    MODE m = conf->mode;
    UT_array *COUNT_LEAF;
    UT_array *COUNT_INTERIOR;
    utarray_new(COUNT_LEAF, &flowkey_icd);
    utarray_new(COUNT_INTERIOR, &flowkey_icd);
    //    printf("++++ calc threshold \n");
    compute_cur_count(TREE, COUNT_LEAF, COUNT_INTERIOR, m);
    uint64_t total_threshold = compute_total_threshold(TREE, COUNT_LEAF, COUNT_INTERIOR);
    uint64_t threshold = compute_threshold(TREE, COUNT_LEAF, COUNT_INTERIOR);
    utarray_free(COUNT_INTERIOR);
    utarray_free(COUNT_LEAF);
    thresholds[0] = total_threshold;
    thresholds[1] = threshold;

}

void calc_thresholds_fix_counters(ft_config_t *conf, uint64_t * thresholds,PROTO proto, COUNTMODE countmode) {
    tree_node **TREE = &conf->TREE;
    MODE m = conf->mode;
    UT_array *COUNT_LEAF;
    UT_array *COUNT_INTERIOR;
    utarray_new(COUNT_LEAF, &flowkey_icd);
    utarray_new(COUNT_INTERIOR, &flowkey_icd);
    compute_cur_count_fix_counters(TREE, COUNT_LEAF, COUNT_INTERIOR, m,proto,countmode);
    uint64_t total_threshold = compute_total_threshold(TREE, COUNT_LEAF, COUNT_INTERIOR);
    uint64_t threshold = compute_threshold(TREE, COUNT_LEAF, COUNT_INTERIOR);
    utarray_free(COUNT_INTERIOR);
    utarray_free(COUNT_LEAF);
    thresholds[0] = total_threshold;
    thresholds[1] = threshold;

}

uint64_t compute_total_threshold(tree_node **TREE, UT_array *COUNT_LEAF, UT_array *COUNT_INTERIOR) {
    UT_array *nums;
    UT_icd uint64_t_icd = {sizeof(uint64_t), NULL, NULL, NULL};
    utarray_new(nums, &uint64_t_icd);
    tree_node **flow_key;
    for (flow_key = (tree_node **) utarray_front(COUNT_INTERIOR);
         flow_key != NULL; flow_key = (tree_node **) utarray_next(COUNT_INTERIOR, flow_key)) {
        tree_node *node = *flow_key;
        utarray_push_back(nums, &node->total_stat);
    }
    utarray_sort(nums, &sort_fun);
    unsigned int size = (uint32_t) utarray_len(nums);
    unsigned int value = (4 * size) / 5;

    if (value < 3) value = 3;
    if (value > size) value = size;

    unsigned int index = value - 1;
    uint64_t *threshold_total, *thresh_dummy;
    threshold_total = (uint64_t * )utarray_eltptr(nums, index);
    uint64_t thresh_copy = 1;
    if(threshold_total)    thresh_copy = *threshold_total;
     //printf("thresh_total was NULL, num_nodes %lu, index= %d, value=%d, %lu\n",HASH_COUNT(*TREE), index, value, size );
    if (thresh_copy < 1) thresh_copy = 1;
    utarray_free(nums);
    return thresh_copy;
}

int sort_fun(const void *a, const void *b) {
    uint64_t _a = *(const uint64_t *) a;
    uint64_t _b = *(const uint64_t *) b;
    return (_a < _b) ? -1 : (_a > _b);
}

uint64_t compute_threshold(tree_node **TREE, UT_array *COUNT_LEAF, UT_array *COUNT_INTERIOR) {
    UT_array *nums;
    UT_icd uint64_t_icd = {sizeof(uint64_t), NULL, NULL, NULL};
    utarray_new(nums, &uint64_t_icd);
    tree_node **flow_key;
    for (flow_key = (tree_node **) utarray_front(COUNT_LEAF);
         flow_key != NULL; flow_key = (tree_node **) utarray_next(COUNT_LEAF, flow_key)) {
        tree_node *node = *flow_key;
        utarray_push_back(nums, &node->stats->count_leaf);
    }
    utarray_sort(nums, &sort_fun);
    unsigned int size = (uint32_t) utarray_len(nums);
    unsigned int value = size / 4;
    if (value < 3) value = 3;
    if (value > size) value = size;
    unsigned int index = value - 1;
    uint64_t *threshold;
    threshold = (uint64_t * )utarray_eltptr(nums, index);

    uint64_t thresh_copy = 1;
    if(threshold) thresh_copy = *threshold;
    if (thresh_copy < 1) thresh_copy = 1;
    utarray_free(nums);

    return thresh_copy;
}

void do_reclaim(uint64_t threshold, uint64_t threshold_total, ft_config_t *conf) {
    tree_node **TREE = &conf->TREE;
    uint64_t lcount = 0, lcurcount = 0, total = 0;
    uint32_t todelete = 0, notdeleted = 0, leafs = 0, notleafs = 0, todelete2 = 0;
    MODE m = conf->mode;
    int isleaf;
    tree_node *node, *tmp;
    uint32_t too_early_to_delete = 0;
    node, tmp = NULL;
    int res = 0;
    HASH_ITER(hh, *TREE, node, tmp) {
        total++;
        isleaf = node->flags.leaf;
        if (is_leaf(node, m) || utarray_len(node->children) == 0) isleaf = 1;
        if ((GET_TOTAL_COMP(node)) <= threshold) lcurcount++;
        if (node->total_stat <= threshold_total) lcount++;
        if (isleaf) leafs++;
	if(node->parent != NULL){
	  if (isleaf && GET_TOTAL_COMP(node) <= threshold)
	    {
	      res = (conf->allocation_mode==DEFAULT_MODE) ? delete_node(node, conf) : delete_node_no_free(node,conf);
	      todelete++;
	    }
	  if (!isleaf) notleafs++;
	  if (!isleaf && (GET_TOTAL_COMP(node)) <= threshold) {
	    if (node->total_stat <= threshold_total) {
	      res = (conf->allocation_mode==DEFAULT_MODE) ? delete_node(node, conf) : delete_node_no_free(node,conf);
	      todelete2++;
            } else {
	      notdeleted++;
            }
	  }
	}
    }

}

void do_reclaim_fix_counters(uint64_t threshold, uint64_t threshold_total, ft_config_t *conf, PROTO proto, COUNTMODE countmode) {
    tree_node **TREE = &conf->TREE;
    uint64_t lcount = 0, lcurcount = 0, total = 0;
    uint32_t todelete = 0, notdeleted = 0, leafs = 0, notleafs = 0, todelete2 = 0;
    MODE m = conf->mode;
    int isleaf;
    tree_node *node, *tmp;
    uint32_t too_early_to_delete = 0;
    node, tmp = NULL;
    int res = 0;
    HASH_ITER(hh, *TREE, node, tmp) {
        total++;
        isleaf = node->flags.leaf;
        uint32_t tmp_total_comp = 0;
        if (proto == ALL)
            tmp_total_comp = node->comp_counters[countmode] + node->comp_counters[countmode + 3];
        else
            tmp_total_comp = node->comp_counters[proto*3 + countmode];
        if (is_leaf(node, m) || utarray_len(node->children) == 0) isleaf = 1;
        if (tmp_total_comp <= threshold) lcurcount++;
        if (node->total_stat <= threshold_total) lcount++;
        if (isleaf) leafs++;
        if(node->parent != NULL){
            if (isleaf && tmp_total_comp <= threshold)
            {
                res = (conf->allocation_mode==DEFAULT_MODE) ? delete_node(node, conf) : delete_node_no_free(node,conf);
                todelete++;
            }
            if (!isleaf) notleafs++;
            if (!isleaf && tmp_total_comp <= threshold) {
                if (node->total_stat <= threshold_total) {
                    res = (conf->allocation_mode==DEFAULT_MODE) ? delete_node(node, conf) : delete_node_no_free(node,conf);
                    todelete2++;
                } else {
                    notdeleted++;
                }
            }
        }
    }

}
void do_reclaim_precise(uint64_t threshold, uint64_t threshold_total,
			uint32_t target, ft_config_t *conf) {
    tree_node **TREE = &conf->TREE;
    uint64_t total = 0;
    uint32_t todelete = 0, notdeleted = 0, todelete2 = 0;
    MODE m = conf->mode;
    int isleaf;
    tree_node *node, *tmp;
    node, tmp = NULL;
    int res = 0; 
    HASH_ITER(hh, *TREE, node, tmp) {
        total++;
        isleaf = node->flags.leaf;
        if (is_leaf(node, m) || utarray_len(node->children) == 0) isleaf = 1;
	if(node->parent != NULL){
	  if (isleaf && GET_TOTAL_COMP(node) <= threshold)
	    {	  
	      res = (conf->allocation_mode==DEFAULT_MODE) ? delete_node(node, conf) : delete_node_no_free(node,conf); 	 
	      todelete++;
	    }
	  if (!isleaf && (GET_TOTAL_COMP(node)) <= threshold) {
	    if (node->total_stat <= threshold_total) {
	      res = (conf->allocation_mode==DEFAULT_MODE) ? delete_node(node, conf) : delete_node_no_free(node,conf);	 
	      todelete2++;
            } else {
	      notdeleted++;
            }
	  }
	}
	if(conf->mem <= target)  return;
    }
    
}

void compress_precisely_to_target(ft_config_t *conf, uint64_t count){
    conf->mem = HASH_COUNT(conf->TREE);
    uint64_t target = conf->mem_threshold;
    if (count > 0) {
        target = count;
    }
    uint32_t iteration = 0 ;
    uint64_t threshs[2] = {0,0};
    calc_thresholds(conf, threshs);
    while (conf->mem > target && conf->mem > 1 ) {
        uint64_t total_threshold = threshs[0];
	uint64_t threshold = threshs[1];
        conf->max_threshold = conf->max_threshold>threshold ? conf->max_threshold : threshold;
        do_reclaim_precise(threshold, total_threshold, target, conf);	
        calc_thresholds(conf, threshs);
        iteration++;
    }
    clean_up_tree(conf);
}

void compress_to_target(ft_config_t *conf, uint64_t count) {
    conf->mem = HASH_COUNT(conf->TREE);
    uint64_t target = conf->mem_threshold;
    if (count > 0) {
        target = count;
    }
    uint32_t iteration = 0 ;
    uint64_t threshs[2] = {0,0};
    calc_thresholds(conf, threshs);
    while (conf->mem > target && conf->mem > 1 ) {
        uint64_t total_threshold = threshs[0];
	uint64_t threshold = threshs[1];
        conf->max_threshold = conf->max_threshold>threshold ? conf->max_threshold : threshold;
        do_reclaim(threshold, total_threshold, conf);
        calc_thresholds(conf, threshs);
        iteration++;
    }
    clean_up_tree(conf);
}

void compress_to_target_fix_counters(ft_config_t *conf, uint64_t count, PROTO proto, COUNTMODE countmode) {
    conf->mem = HASH_COUNT(conf->TREE);
    uint64_t target = conf->mem_threshold;
    if (count > 0) {
        target = count;
    }
    uint32_t iteration = 0 ;
    uint64_t threshs[2] = {0,0};
    calc_thresholds_fix_counters(conf, threshs, proto,countmode);
    while (conf->mem > target && conf->mem > 1 ) {
        uint64_t total_threshold = threshs[0];
        uint64_t threshold = threshs[1];
        conf->max_threshold = conf->max_threshold>threshold ? conf->max_threshold : threshold;
        do_reclaim_fix_counters(threshold, total_threshold, conf, proto, countmode);
        calc_thresholds_fix_counters(conf, threshs,proto, countmode);
        iteration++;
    }
    clean_up_tree(conf);
}

void reclaim(ft_config_t *conf) {
    compress_precisely_to_target(conf, 0);
}

void clean_up_tree(ft_config_t *conf) {
    tree_node **TREE = &conf->TREE;
    tree_node *node, *tmp;
    HASH_ITER(hh, *TREE, node, tmp) {
            free(node->stats);
            node->stats = NULL;
    }
}




ft_config_t *merge_multiple_trees(UT_array *list_trees, MODE m) {
    if (!list_trees || utarray_len(list_trees) == 0) return NULL;
    ft_config_t **item = NULL;
    ft_config_t *conf = NULL;
    for (item = (ft_config_t **) utarray_front(list_trees);
         item != NULL; item = (ft_config_t **) utarray_next(list_trees, item)) {
        if (*item){
            conf = clone_tree(*item);
            break;
        }
    }
    if (utarray_len(list_trees) == 1) return conf;
    if (conf) {
        int i = 0;
        item = NULL;
        //	printf("merge_multiple_trees %lu\n",utarray_len(list_trees));
        for (item = (ft_config_t **) utarray_front(list_trees);
             item != NULL; item = (ft_config_t **) utarray_next(list_trees, item)) {
            ft_config_t *conf2 = *item;
            if (conf2 && i > 0) {
                merge_trees(conf, conf2);
            }
            i++;
        }
        return conf;
    }
    return NULL;
}
ft_config_t *merge_multiple_trees_with_growth_factor(UT_array *list_trees, MODE m) {
    if (!list_trees || utarray_len(list_trees) == 0) return NULL;

    ft_config_t **item = NULL;
    ft_config_t *conf = NULL;
    for (item = (ft_config_t **) utarray_front(list_trees);
         item != NULL; item = (ft_config_t **) utarray_next(list_trees, item)) {
        if (*item){
            conf = clone_tree(*item);
            break;
        }
    }

//    uint32_t tree1_numnodes = HASH_COUNT(conf->TREE);
    if (utarray_len(list_trees) == 1) return conf;
    if (conf) {
        int i = 0;
        item = NULL;
        //	printf("merge_multiple_trees %lu\n",utarray_len(list_trees));
        for (item = (ft_config_t **) utarray_front(list_trees);
             item != NULL; item = (ft_config_t **) utarray_next(list_trees, item)) {
            ft_config_t *conf2 = *item;
            if (conf2 && i > 0) {
                double growth_factor = 0.1;
                uint32_t tree_size_1 = HASH_COUNT(conf->TREE);
                uint32_t tree_size_2 = HASH_COUNT(conf2->TREE);
                uint32_t target_size = tree_size_1 > tree_size_2 ? tree_size_1 : tree_size_2;
                target_size += (uint32_t) ((double) target_size * growth_factor);
                merge_trees(conf, conf2);
                conf->granularity =
                        conf->granularity + conf2->granularity;
                conf->timestamp = conf->timestamp;
                conf->site_id = -1;
                target_size = target_size < HASH_COUNT(conf->TREE) ? target_size : HASH_COUNT(
                        conf->TREE);
                if (tree_size_1 > 500000)
                    compress_to_target(conf, target_size);

            }
            i++;
        }
        return conf;
    }
    return NULL;
}

int is_tree_convertible(ft_config_t *conf_dest, ft_config_t *conf_src){
  MODE src_mode = conf_src->mode;
  MODE dst_mode = conf_dest->mode;
  void (*conversion_func)(uint32_t * , uint32_t *) = (MODE_CONVERSION_TABLE[src_mode][dst_mode]);
  return (conversion_func!=NULL);
}


void convert_flow_key_modes(uint32_t * dst_flow_key, uint32_t *src_flow_key, MODE dst_mode , MODE src_mode){
  void (*conversion_func)(uint32_t * , uint32_t *) = (MODE_CONVERSION_TABLE[src_mode][dst_mode]);
  if(conversion_func){
    conversion_func(dst_flow_key, src_flow_key);
  }

}
void update_existing_or_create_add_node(uint32_t *flow_key_to_add, tree_node *node_wt_meta_data, ft_config_t *ft_to_update){
  MODE m = ft_to_update->mode;
  tree_node *node_to_update = NULL;
  node_to_update = get_flow_hmap_((const tree_node **) ft_to_update, flow_key_to_add, m);
  if (node_to_update) {
    ADD_COMP_COUNTERS(node_to_update->comp_counters,node_wt_meta_data->comp_counters,6);
  }else{
    add_tree_node(flow_key_to_add, 0, node_wt_meta_data->comp_counters, 6, ft_to_update);
  }


}

int convert_tree_modes(ft_config_t *conf_dest, ft_config_t * conf_src){
  /* iterate in the src tree
     Get the appropriate element in the src flow_key:
        appropriate element is the value or set of values in the src_flow_key that should be added to the destination
	flow_key
     find the the corresponding node in the destination:
     if the corresponding node in the destination exists, add the node contribution(comp_pop) to the node. Otherwise
     create a new node.
   */
  if(!is_tree_convertible(conf_dest, conf_src))
    return 1;

  tree_node **src_hash_tbl = &conf_src->TREE;
  tree_node **dst_hash_tbl = & conf_dest->TREE;
  tree_node *src_node , *tmp_src;
  MODE dst_mode = conf_dest->mode;
  MODE  m = conf_dest->mode;
  MODE src_mode = conf_src->mode;
  uint32_t dst_flow_key[DIM];
  uint32_t * src_flow_key = NULL;
  HASH_ITER(hh, *src_hash_tbl, src_node , tmp_src){
    src_flow_key = src_node->flow_key;
    convert_flow_key_modes(dst_flow_key, src_flow_key,dst_mode,  src_mode);
    update_existing_or_create_add_node(dst_flow_key,src_node, conf_dest);
  }
  return 0;
}


void merge_trees(ft_config_t *conf_flow1, ft_config_t *conf_flow2) {
    MODE m = conf_flow1->mode;
    tree_node **flow1 = &conf_flow1->TREE;
    tree_node **flow2 = &conf_flow2->TREE;
    tree_node *flow2_node, *tmp;
    uint32_t num_missed = 0;
    uint32_t num_was = 0;
    //printf("merge tree, conf1 %d nodes , conf2 %d nodes\n", HASH_COUNT(conf_flow1->TREE), HASH_COUNT(conf_flow2->TREE));
    HASH_ITER(hh, *flow2, flow2_node, tmp) {
        uint32_t *flow_key = flow2_node->flow_key;
        tree_node *flow1_node;
        flow1_node = get_flow_hmap_((const tree_node **) flow1, flow_key, m);
        if (flow1_node) {
	  ADD_COMP_COUNTERS(flow1_node->comp_counters,flow2_node->comp_counters,6);
			    //flow1_node->comp_pop += flow2_node->comp_pop;
            num_was++;
        } else {
	  uint64_t fake_counters[6] = {0,0,0,0,0,0};
	  add_tree_node(flow2_node->flow_key, 1,fake_counters, 6, conf_flow1);
            flow1_node = get_flow_hmap_((const tree_node **) flow1, flow_key, m);
	    COPY_COMP_COUNTERS(flow1_node->comp_counters,flow2_node->comp_counters, 6);
            //flow1_node->comp_pop = flow2_node->comp_pop;
            num_missed++;
        }

    }
    //    printf("merge tree, num_mised %lu nodes , num_not_missed %lu nodes, resulting count %d\n", num_missed, num_was,  HASH_COUNT(conf_flow1->TREE));

}

int alloc_nodes_push_stack(ft_config_t *conf){
  MODE m = conf->mode;
  uint32_t flow_key[DIM * 2];
  memset(flow_key, 0, MODE_SIZES[m]);
  conf->node_stack = stack_new(conf->mem_max);
  for(uint32_t j = 0 ; j < conf->mem_max; j++){
    tree_node *node = create_tree_node_from_flow(flow_key, m);
    stack_push(conf->node_stack, (void *)node);
  }
}

int alloc_stack_from_buff(ft_config_t *conf){
  tree_node *tree_nodes_buff =conf->node_buffers;
  uint32_t *tree_keys_buff = conf->flow_keys;
  MODE m = conf->mode;
  conf->node_stack = stack_new(conf->mem_max);
  for(uint32_t j = 0 ; j < conf->mem_max ; j++){
    tree_node *node = &tree_nodes_buff[j];
    node->flow_key = tree_keys_buff;
    init_node(node);
    stack_push(conf->node_stack , (void *)node);
    tree_keys_buff += 2 *DIM;
  }
}

int alloc_nodes_bulk(ft_config_t *conf){
  MODE m = conf->mode;
  tree_node *tree_nodes_buff = (tree_node *)calloc(conf->mem_max, sizeof(tree_node ));
  uint32_t *tree_keys_buff = (uint32_t *)calloc(((conf->mem_max) * DIM * 2), sizeof(uint32_t));
  conf->node_buffers = tree_nodes_buff;
  conf->flow_keys = tree_keys_buff;
}

int allocate_memory_tree(ft_config_t *conf){
  switch (conf->allocation_mode){
  case BULK_AND_STACK:
    alloc_nodes_bulk(conf);
    alloc_stack_from_buff(conf);
    break;
  case BULK_ONLY:
    alloc_nodes_bulk(conf);
    break;
  case STACK_ONLY:
    alloc_nodes_push_stack(conf);
    break;
  default:
    break;
  }
  return -1;
}

void shallow_copy_tree(ft_config_t *conf_dst, ft_config_t *conf_src){
    MODE m = conf_src->mode;
    conf_dst->mode = m;
    conf_dst->mem_threshold = conf_src->mem_threshold;
    conf_dst->site_id = conf_src->site_id;
    conf_dst->granularity = conf_src->granularity;
    conf_dst->mem = 0;
    conf_dst->hash_count = conf_src->hash_count;
    conf_dst->tree_add = conf_src->tree_add;
    conf_dst->tree_delete = conf_src->tree_delete;
    conf_dst->mem_max = conf_src->mem_max;
    conf_dst->timestamp = conf_src->timestamp;
    conf_dst->memory_threshold = conf_src->memory_threshold;
    conf_dst->mem_threshold = conf_src->mem_threshold;
    conf_dst->n_reclaim = conf_src->n_reclaim;
    conf_dst->n_print = conf_src->n_print;
    conf_dst->n = conf_src->n;
    conf_dst->time = conf_src->time;
    conf_dst->time_start = conf_src->time_start;
    conf_dst->time_next = conf_src->time_next;
    conf_dst->time_int = conf_src->time_int;

}
ft_config_t *clone_bulk_tree(ft_config_t *tree_to_clone){
  ft_config_t *cloned_tree = create_ft_config();
  shallow_copy_tree(cloned_tree, tree_to_clone);
  uint32_t tree_size = HASH_COUNT(tree_to_clone->TREE);
  cloned_tree->mem_max = tree_size;
  cloned_tree->allocation_mode = BULK_ONLY;
  MODE m = cloned_tree->mode; 
  allocate_memory_tree(cloned_tree);  
  tree_node *tree_nodes = cloned_tree->node_buffers;
  uint32_t *tree_keys = cloned_tree->flow_keys;
  memcpy(tree_keys, tree_to_clone->flow_keys, MODE_SIZES[m]*tree_size);
  tree_node **TREE = &cloned_tree->TREE;
  uint32_t *curr_key = tree_keys; 
  for(uint32_t j = 0 ; j < tree_size ; j++){
    tree_node *nd = &tree_nodes[j];
    init_node(nd);
    nd->flow_key = curr_key;
    curr_key += 2 * DIM;
    add_node_hmap(TREE, nd, m);
  }
  tree_node **flow1 = &cloned_tree->TREE;
  tree_node **flow2 = &tree_to_clone->TREE;
  tree_node *flow2_node, *tmp;
  HASH_ITER(hh, *flow2, flow2_node, tmp) {
    uint32_t *flow_key = flow2_node->flow_key;
    tree_node *flow1_node;
    flow1_node = get_flow_hmap_((const tree_node **) flow1, flow_key, m);
    if (!flow1_node) {
      log_fatal("clonning the bulk trees failed!\n");
      exit(-20);
    }    
    COPY_COMP_COUNTERS(flow1_node->comp_counters,flow2_node->comp_counters,6);
			   //flow1_node->comp_pop = flow2_node->comp_pop;
    flow1_node->total_stat = flow2_node->total_stat;
    tree_node *parent = NULL;
    if (flow2_node->parent) {
      uint32_t *parent_flow = flow2_node->parent->flow_key;
      parent = get_flow_hmap_((const tree_node **) flow1, parent_flow, m);
      if (!parent) {
	log_fatal("find parnet in clonning the bulk trees failed!\n");
	exit(-21);
      }
      flow1_node->parent = parent;
      if (!check_node_in_sons(flow1_node, parent, m)) {
	add_to_children(flow1_node, parent);
      }
    }else{
      cloned_tree->root = flow1_node; 
    }
  }
  cloned_tree->mem = HASH_COUNT(cloned_tree->TREE);
  return cloned_tree;

}

ft_config_t *clone_tree(ft_config_t *conf) {
    ft_config_t *cnf = create_ft_config();
    MODE m = conf->mode;
    shallow_copy_tree(cnf, conf);
    add_root(cnf);
    tree_node **flow1 = &cnf->TREE;
    tree_node **flow2 = &conf->TREE;
    tree_node *flow2_node, *tmp;
    HASH_ITER(hh, *flow2, flow2_node, tmp) {
        uint32_t *flow_key = flow2_node->flow_key;
        tree_node *flow1_node;
        flow1_node = get_flow_hmap_((const tree_node **) flow1, flow_key, m);
        if (!flow1_node) {
            flow1_node = create_tree_node_from_flow(flow_key, m);
            add_node_hmap((tree_node **) flow1, flow1_node, m);
        }

	COPY_COMP_COUNTERS(flow1_node->comp_counters,flow2_node->comp_counters,6);
			   //flow1_node->comp_pop = flow2_node->comp_pop;
        flow1_node->total_stat = flow2_node->total_stat;
        tree_node *parent = NULL;
        if (flow2_node->parent) {
            uint32_t *parent_flow = flow2_node->parent->flow_key;
            parent = get_flow_hmap_((const tree_node **) flow1, parent_flow, m);
            if (!parent) {
                parent = create_tree_node_from_key(parent_flow, m);
                add_node_hmap((tree_node **) flow1, parent, m);
            }
            flow1_node->parent = parent;
            if (!check_node_in_sons(flow1_node, parent, m)) {
                add_to_children(flow1_node, parent);
            }
        }
    }
    cnf->mem = HASH_COUNT(cnf->TREE);
    return cnf;
}
void free_multiple_trees(UT_array *list_trees){
  if(list_trees==NULL)return;
    ft_config_t **item = NULL;
    ft_config_t *conf = NULL;
    for (item = (ft_config_t **) utarray_front(list_trees);
	 item != NULL; item = (ft_config_t **) utarray_next(list_trees, item)) {
      ft_config_t *conf2 = *item;
      if(conf2!=NULL) free_ft_config(conf2);
    }
    utarray_free(list_trees);
}

//killer TODO: doesn't work because skips negative values
ft_config_t *diff_multiple_trees(UT_array *list_trees, MODE m) {
    if (!list_trees) return NULL;
    ft_config_t **item = NULL;
    ft_config_t *conf = NULL;
    item = (ft_config_t **) utarray_front(list_trees);
    if (*item) conf = clone_tree(*item);

    if (conf) {
        int i = 0;
        item = NULL;
        printf("merge_multiple_trees %lu\n", utarray_len(list_trees));
        for (item = (ft_config_t **) utarray_front(list_trees);
             item != NULL; item = (ft_config_t **) utarray_next(list_trees, item)) {
            ft_config_t *conf2 = *item;
            if (conf2 && i > 0) {
                diff_trees_stats(conf, conf2);

            }
            i++;
        }
        return conf;
    }
    return NULL;
}


/*
 * This function performs diff operation on two trees, deleting non-root nodes with diff <=0.
 */
void diff_trees(ft_config_t *conf1, ft_config_t *conf2) {
    tree_node **tree1 = &conf1->TREE;
    tree_node **tree2 = &conf2->TREE;
    MODE m = conf1->mode;
    tree_node *tree1_node, *tmp;
    HASH_ITER(hh, *tree1, tree1_node, tmp) {
        uint32_t *flow_key = tree1_node->flow_key;
        tree_node *tree2_node;
        tree2_node = get_flow_hmap_((const tree_node **) tree2, flow_key, m);
        if (tree2_node) {
            long long int diff;
            diff = (long long int) tree1_node->total_stat - (long long int) tree2_node->total_stat;
            if (diff > 100000) {
                printf("( %d|%d,%lu ) - ( %d|%d,%lu ) = ", tree1_node->flow_key[0], tree1_node->flow_key[1],
                       tree1_node->total_stat, tree2_node->flow_key[0], tree2_node->flow_key[1],
                       tree2_node->total_stat);
                printf(" %ld\n", diff);
            }

                if (diff <= 0) {
                if (!node_equals(tree1_node, conf1->root, m)) {
                    delete_node(tree1_node, conf1);
                } else {
                    tree1_node->total_stat = 0;
                }
            } else {
                tree1_node->total_stat = (uint64_t) diff;
            }
        }
    }
}

/**
 * This function performs diff operation on two trees, but unlike diff_trees, does consider negative changes in trees, meaning that it doesn't remove nodes with diff < 0.
 * In this function, node->stat->done_stat is used to store sign values.
 * 0 or null means it's untouched, 1 means positive, 2 means negative.
 * */
void diff_trees_stats(ft_config_t *conf1, ft_config_t *conf2) {
    tree_node **tree1 = &conf1->TREE;
    tree_node **tree2 = &conf2->TREE;
    MODE m = conf1->mode;
    tree_node *tree1_node, *tmp;
    HASH_ITER(hh, *tree1, tree1_node, tmp) {
        uint32_t *flow_key = tree1_node->flow_key;
        tree_node *tree2_node;
        if (!tree1_node->stats) {
            tree1_node->stats = calloc(1, sizeof(tree_node_stats));
            //reset_node_stats(tree1_node);
        }
        tree2_node = get_flow_hmap_((const tree_node **) tree2, flow_key, m);
        if (tree2_node) {
            uint64_t diff;
            if (tree1_node->stats->done_stat == 80) {//if positive
                if (tree2_node->total_stat  <= tree1_node->total_stat) {
                    diff = tree1_node->total_stat - tree2_node->total_stat;
                    tree1_node->stats->done_stat = 80; //it's positive ascii for P = 80
                } else {
                    diff = tree2_node->total_stat - tree1_node->total_stat;
                    tree1_node->stats->done_stat = 78; //it's negative ascii for N = 78
                }
            } else if (tree1_node->stats->done_stat == 78) {//if negative
                //if tree1_node pop is negative, knowing that tree2_node pop is always positive
                diff = tree1_node->total_stat + tree2_node->total_stat;
                tree1_node->stats->done_stat = 78;
            } else { //if ==0 or if null --> meaning: if it is untouched.
                if (tree2_node->total_stat  <= tree1_node->total_stat){
                    diff = tree1_node->total_stat - tree2_node->total_stat;
                    tree1_node->stats->done_stat = 80;
                }
                else {
                    diff = tree2_node->total_stat - tree1_node->total_stat;
                    tree1_node->stats->done_stat = 78;
                }
            }
            tree1_node->total_stat = diff;
            //done_stat zero (stats null) if tree is not diffed

//            printf("done_stat=%d", tree1_node->stats->done_stat);
//            printf("( %d|%d,%lu ) - ( %d|%d,%lu ) = ", tree1_node->flow_key[0], tree1_node->flow_key[1],
//                   tree1_node->total_stat, tree2_node->flow_key[0], tree2_node->flow_key[1],
//                   tree2_node->total_stat);
//            printf(" %ld\n", diff);

        }
    }
}

void add_packet_bin(packet_bin *packet, ft_config_t *conf) {
  MODE m = conf->mode;
  const mask_idx idxs = MASK_IDXs[m];
  uint32_t f[DIM * 2];
  memset(f, 0, MODE_SIZES[m]);
  uint32_t parent[DIM * 2];
  memset(f, 0, MODE_SIZES[m]);
  tree_node **TREE = &conf->TREE;
  tree_node *toReturn = NULL;
  int prefixes[DIM];
  for (int j = 0; j < DIM; j++) {
    prefixes[j] = MAX_PREFIXES[m].prefs[j];
  }
  int max_length = MAX_PREFIXES[m].prefs[0];;
  int add = 0;
  int found = 0;
  create_flow_from_packet_bin(packet, prefixes, f, m);
  memcpy(parent, f, MODE_SIZES[m]);
  uint64_t counters[6] = {0, 0, 0, 0, 0, 0};
  int start_idx = (packet->proto == 6) ? 0 : 3;
  memcpy(((&counters[0]) + start_idx), packet->packet_count, sizeof(uint64_t) * 3);
  while (!found && prefixes[0] >= 0) {
    tree_node *node = NULL;
    conf->hash_count++;
    node = get_flow_hmap_((const tree_node **) TREE, (const uint32_t *) parent, m);
    if (node) {
      if (!add) {
	ADD_COMP_COUNTERS(node->comp_counters, counters, 6);
      }
      found = 1;
    } else {
      int r = 0;
      if ((prefixes[0] % INCREM == 0)) {
	if (!(prefixes[0] == max_length))
	  r = rand_r(&(conf->seed)) % 1000;
	if (r < 300) {
	  if (conf->mem < conf->mem_max) {
	    switch(conf->allocation_mode){
	    case DEFAULT_MODE:       
	      node = add_tree_node(parent, add, counters,6,conf);
	      break;
	    case BULK_AND_STACK:
	    case STACK_ONLY:
	      node = add_tree_node_from_stack(parent, add, counters, 6, conf);		       break;
	    default:
	      log_fatal("attampting to add a node to an immutable tree");
	      exit(-12);
	      break;
	    }

	    //
	    if (!add) toReturn = node;
	    add = 1;
	  } else {
	    reclaim(conf);
	    conf->mem_exceeded++;
	  }
	}
      }
    }
    for (int k = 0; k < DIM; k++) {
      int ip_or_port = idxs.idx[k];
      int inc = INCREM;
      inc -= ip_or_port;
      prefixes[k] -= inc;
    }
    memcpy(f, parent, MODE_SIZES[m]);
    parent_flow(f, parent, m);
  }

}
void add_packet_bin_unlim(packet_bin *packet, ft_config_t *conf) {
  MODE m = conf->mode;
  const mask_idx idxs = MASK_IDXs[m];
  uint32_t f[DIM * 2];
  memset(f, 0, MODE_SIZES[m]);
  uint32_t parent[DIM * 2];
  memset(f, 0, MODE_SIZES[m]);
  tree_node **TREE = &conf->TREE;
  tree_node *toReturn = NULL;
  int prefixes[DIM];
  for (int j = 0; j < DIM; j++) {
    prefixes[j] = MAX_PREFIXES[m].prefs[j];
  }
  int max_length = MAX_PREFIXES[m].prefs[0];;
  int add = 0;
  int found = 0;
  create_flow_from_packet_bin(packet, prefixes, f, m);
  memcpy(parent, f, MODE_SIZES[m]);
  uint64_t counters[6] = {0, 0, 0, 0, 0, 0};
  int start_idx = (packet->proto == 6) ? 0 : 3;
  memcpy(((&counters[0]) + start_idx), packet->packet_count, sizeof(uint64_t) * 3);
  while (!found && prefixes[0] >= 0) {
    tree_node *node = NULL;
    conf->hash_count++;
    node = get_flow_hmap_((const tree_node **) TREE, (const uint32_t *) parent, m);
    if (node) {
      if (!add) {
	ADD_COMP_COUNTERS(node->comp_counters, counters, 6);
      }
      found = 1;
    } else {
      int r = 0;
      if ((prefixes[0] % INCREM == 0)) {
	switch(conf->allocation_mode){
	case DEFAULT_MODE:       
	  node = add_tree_node(parent, add, counters,6,conf);
	    break;
	case BULK_AND_STACK:
	case STACK_ONLY:
	  node = add_tree_node_from_stack(parent, add, counters, 6, conf);
	  break;
	default:
	  log_fatal("attampting to add a node to an immutable tree");
	  exit(-12);
	  break;
	}
	
	//
	if (!add) toReturn = node;
	add = 1;

      }
    }
 
    for (int k = 0; k < DIM; k++) {
      int ip_or_port = idxs.idx[k];
      int inc = INCREM;
      inc -= ip_or_port;
      prefixes[k] -= inc;
    }
    memcpy(f, parent, MODE_SIZES[m]);
    parent_flow(f, parent, m);
  }
}



void fix_root_ptr(ft_config_t *tree_to_fix){
    tree_node *tree_hash_tbl = tree_to_fix->TREE;
    MODE m = tree_to_fix->mode;
    uint32_t root_key[DIM*2];
    root_flow(root_key, m);
    tree_node *root = NULL;
    root = get_flow_hmap_((const tree_node **) &tree_hash_tbl, (const uint32_t *) root_key, m);
    if(root){
        tree_to_fix->root = root;
        root->parent = NULL;
    }else{
        printf("root not found\n");
    }


}
