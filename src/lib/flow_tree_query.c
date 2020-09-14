#include "flow_tree_query.h"

void process_query(char **flow_str, ft_config_t *TREE_config, MODE m, int k, char *buff, uint32_t buff_size, uint64_t thresh) {
//    ft_config_t *TREE2_config = clone_tree(TREE_config);
    tree_node **TREE = &TREE_config->TREE;
    uint32_t f[DIM * 2];
    uint64_t pop = 0;
    tree_node *node;
    printf("___________>%s\n",*flow_str);
    char flow_str_backup[1000];
    strncpy(flow_str_backup, *flow_str, 999);
    flow_str_backup[999] = '\0';


    create_flow_from_tree_file(flow_str, f, m);

    node = get_flow_hmap_((const tree_node **) TREE, (const uint32_t *) f, m);
    if (node) {
        sprintf(buff, "%s-%lu-%lu\n", flow_str_backup, node->total_stat, node->comp_pop);//(node->comp_counters[0] + node->comp_counters[3]));
        printf("---> I want to print pops: ");
        printf("total pop is %lu \n", node->total_stat);
        for (int i = 0; i < 6; i++) {
            printf("comp_pop %d is %lu \n", i, node->comp_counters[i]);
        }
    } else {
        node = create_tree_node_from_flow(f, m);
        tree_node *parent;
        if (node->parent) {
            parent = find_parents(node, TREE, m);
        } else parent = node;

        print_node(parent, m);
        uint64_t estimate = parent->total_stat;
        uint64_t totalson = 0;
        uint64_t parent_count = parent->total_stat;//parent->comp_counters[0] + parent->comp_counters[3];
        tree_node *son = NULL;
        int i = 0;
        tree_node **son_key = NULL;
        for ((son_key = (tree_node **) utarray_front(parent->children));
             son_key != NULL; son_key = (tree_node **) utarray_next(parent->children, son_key)) {
            son = *son_key;
            if (check_include_flow_key(node->flow_key, son->flow_key, m)) {
                totalson += son->total_stat;

            } else {
                estimate -= son->total_stat;
            }

            i++;
        }
        printf("THIS IS AN ESTIMATE ! parent found: %lu|%lu\n ", parent->flow_key[0], parent->flow_key[1]);
        printf("---> I want to print pops: ");
        for (int i = 0; i < 6; i++) {
            printf("pop %d is %lu \n", i, parent->comp_counters[i]);
        }
        sprintf(buff, "ESTIMATE OF %s-%lu\n", *flow_str, estimate);
//        pop = estimate;
//        char res[512];
//        sprintf(buff, "result via parent : %lu-%lu-%lu\n", totalson, totalson + parent_count, estimate);
//        strcat(buff, res);

        if (node->children)utarray_free(node->children);
        free(node->flow_key);
        free(node);
    }
}
void process_query_top_k(char **flow_str, ft_config_t *TREE_config, MODE m, int k, char *buff, uint32_t buff_size, uint64_t thresh) {
//    ft_config_t *TREE2_config = clone_tree(TREE_config);
    tree_node **TREE = &TREE_config->TREE;
    if (k == 0) k = HASH_COUNT(TREE_config->TREE);
//    printf("____________ K IS : %d", k);
    //compress_to_target(TREE2_config, HASH_COUNT(TREE_config->TREE));
    printf("in process_query_top_k first line to process %s\n", *flow_str);
    uint32_t f[DIM * 2];
    tree_node *node;
    create_flow_from_tree_file(flow_str, f, m);
    if (flow_in_hmap((const tree_node **) TREE, (const uint32_t *) f, m)) {
        node = get_flow_hmap_((const tree_node **) TREE, (const uint32_t *) f, m);
        printf("node is going to be in \n");
        BFS_top_k(node, &buff[0], buff_size, TREE, m, k, thresh);

        printf("node is in\n");
    } else {
        node = create_tree_node_from_flow(f, m);
        tree_node *parent;
        if (node->parent) {
            parent = find_parents(node, TREE, m);
        } else parent = node;
        tree_node *son = NULL;
        tree_node **son_key = NULL;
        for ((son_key = (tree_node **) utarray_front(parent->children));
             son_key != NULL; son_key = (tree_node **) utarray_next(parent->children, son_key)) {
            son = *son_key;
            if (check_include_flow_key(node->flow_key, son->flow_key, m)) {
                printf("node is going to be not in\n");
                BFS_top_k(son, &buff[0], buff_size, TREE, m, k, thresh);
                printf("node is not in\n");
            }
        }
    }
//    free_ft_config(TREE2_config);

}
void process_query_top_k_any(char **flow_str, ft_config_t *TREE_config, MODE m, int k, char *buff, uint32_t buff_size, uint64_t thresh) {
//    ft_config_t *TREE2_config = clone_tree(TREE_config);
    if (TREE_config->root == NULL)
        fix_root_ptr(TREE_config);
    tree_node *root = TREE_config->root;
    printf("in process_query_top_k any first line to process %s\n", *flow_str);
    sprintf(&buff[0],"");
    BFS_top_k_any(*flow_str, root, &buff[0], buff_size, &TREE_config->TREE, m, k, thresh);

//    free_ft_config(TREE2_config);
}

void BFS_top_k(tree_node *start_node, char *buff, uint32_t buff_size, tree_node **TREE, MODE m, uint32_t k, uint64_t thresh) {
    heap_t *priority_queue = (heap_t *) calloc(1, sizeof(heap_t));
    tree_node *node, *tmp;
    int buff_tmp_size = 10000;
    char buff_tmp[buff_tmp_size];
    node_to_string_full(start_node,&buff_tmp[0],buff_tmp_size,TREE,m);

    HASH_ITER(hh, *TREE, node, tmp) {
        if (!node->stats) node->stats =(tree_node_stats*) calloc(1, sizeof(tree_node_stats));

        if (check_include_flow_key(start_node->flow_key,node->flow_key,m) && (is_leaf(node, m)|| utarray_len(node->children) == 0)) {
            node->flags.leaf = 1;
            pq_push(priority_queue,node->total_stat,(void*) node);
            node->stats->cson_stat = 0 ;
        }else {
            node->stats->done_stat = 0 ;
            node->stats->cson_stat = utarray_len(node->children);
        }
    }

    uint32_t min_k = (k < HASH_COUNT(*TREE)) ? k : HASH_COUNT(*TREE);

    int tmpindex = 0;
    uint32_t num_bytes = 0;
    while(priority_queue->len > 0){
        tree_node *pop_node = (tree_node *) pq_pop(priority_queue);
        if (tmpindex < min_k && pop_node->total_stat > thresh) {
            tmpindex++;
            char node_buff[1000];
            node_to_string_compact(pop_node, node_buff, m);
            num_bytes += strlen(node_buff) + sprintf(node_buff + strlen(node_buff), "-%lu-%lu-\n",
                                                     pop_node->total_stat, pop_node->comp_pop);

            if (num_bytes + 40 >= buff_size) {
                buff_size = buff_size * 1.3;
                buff = (char *) realloc(buff, buff_size * sizeof(char));
            }

            strcat(buff, node_buff);
            tree_node  *cur_par = pop_node->parent;

            while (cur_par != NULL  && !node_equals(cur_par, start_node, m)) {
                cur_par->total_stat -= pop_node->total_stat;
                cur_par = cur_par->parent;
            }
        } else if (tmpindex >= min_k) break;
        tree_node *tmp_parent = pop_node;

        tree_node * parent = pop_node->parent;
        if (parent) {
            parent->stats->done_stat++;
            if(parent->stats->done_stat == parent->stats->cson_stat){
                pq_push(priority_queue, pop_node->parent->total_stat, (void *) (pop_node->parent));
            }
        }

    }
    free(priority_queue);

}
void BFS_top_k_any(char *flow_str_any_to_search, tree_node *start_node, char *buff, uint32_t buff_size, tree_node **TREE, MODE m, uint32_t k, uint64_t thresh) {
    heap_t *priority_queue = (heap_t *) calloc(1, sizeof(heap_t));

    tree_node *node, *tmp;
    HASH_ITER(hh, *TREE, node, tmp) {
//        printf("node's pop is: %lu\n", node->total_stat);
        if (!node->stats) node->stats =(tree_node_stats*) calloc(1, sizeof(tree_node_stats));
        if (is_leaf(node, m) || utarray_len(node->children) == 0) {
            node->flags.leaf = 1;
            pq_push(priority_queue,node->total_stat,(void*) node);
            node->stats->cson_stat = 0 ;
        }else{
            node->stats->done_stat = 0 ;
            node->stats->cson_stat = utarray_len(node->children);
        }
    }

    uint32_t min_k = (k < HASH_COUNT(*TREE)) ? k : HASH_COUNT(*TREE);
    if (min_k == 0) min_k = HASH_COUNT(*TREE);

    int tmpindex = 0;
    uint32_t num_bytes = 0;

    while(priority_queue->len > 0){
        tree_node *pop_node = (tree_node *) pq_pop(priority_queue);

        char node_buff[1000];
        node_to_string_compact(pop_node, node_buff, m);

        char flow_str_to_search[1000];
        for (int i = 0; i < 1000; i++)
            flow_str_to_search[i] = flow_str_any_to_search[i];

        if (tmpindex < min_k && pop_node->total_stat > thresh && check_inclusion_and_subnode_flowstr(flow_str_to_search,node_buff, m)) {
            tmpindex++;
            char node_buff_ok[1000];
            node_to_string_compact(pop_node, node_buff_ok, m);
            num_bytes += strlen(node_buff_ok) + sprintf(node_buff_ok + strlen(node_buff_ok), "-%lu-%lu\n",
                    pop_node->total_stat, pop_node->comp_pop);//(pop_node->comp_counters[0] + pop_node->comp_counters[3]));

            if (num_bytes + 40 >= buff_size) {
                buff_size = buff_size * 1.3;
                buff = (char *) realloc(buff, buff_size * sizeof(char));
            }

            strcat(buff, node_buff_ok);
            tree_node  *cur_par = pop_node->parent;

            while (cur_par != NULL  && !node_equals(cur_par, start_node, m)) {
                cur_par->total_stat -= pop_node->total_stat;
                cur_par = cur_par->parent;
            }
        } else if (tmpindex >= min_k) break;
        tree_node *tmp_parent = pop_node;

        tree_node * parent = pop_node->parent;
        if (parent) {
            parent->stats->done_stat++;
            if(parent->stats->done_stat == parent->stats->cson_stat){
                pq_push(priority_queue, pop_node->parent->total_stat, (void *) (pop_node->parent));
            }
        }
    }
    free(priority_queue);

}
uint64_t BFS_pop_any(char *flow_str_any_to_search, tree_node *start_node, tree_node **TREE, MODE m, uint32_t k, uint64_t thresh) {
    heap_t *priority_queue = (heap_t *) calloc(1, sizeof(heap_t));
    tree_node *node, *tmp;
    HASH_ITER(hh, *TREE, node, tmp) {

        if (!node->stats) node->stats =(tree_node_stats*) calloc(1, sizeof(tree_node_stats));
        if (is_leaf(node, m) || utarray_len(node->children) == 0) {
            node->flags.leaf = 1;
            pq_push(priority_queue,node->total_stat,(void*) node);
            node->stats->cson_stat = 0 ;
        }else{
            node->stats->done_stat = 0 ;
            node->stats->cson_stat = utarray_len(node->children);
        }
    }

    uint32_t min_k = (k < HASH_COUNT(*TREE)) ? k : HASH_COUNT(*TREE);
    if (min_k == 0) min_k = HASH_COUNT(*TREE);
    printf("min_k = %d\n", min_k);
    uint64_t total_pop = 0;
    int tmpindex = 0;
    while(priority_queue->len > 0){
        tree_node *pop_node = (tree_node *) pq_pop(priority_queue);

        char node_buff[1000];
        node_to_string_compact(pop_node, node_buff, m);
        char flow_str_to_search[1000];
        for (int i = 0; i < 1000; i++)
            flow_str_to_search[i] = flow_str_any_to_search[i];
        int inclusion_flag = 0;
        inclusion_flag = check_inclusion_and_subnode_flowstr(flow_str_to_search, node_buff, m);
//        if (pop_node->flow_key[0] == 1047645969) {
//            printf("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& %s comp_counters[0]=%lu totalstat=%lu check_inclusion=%d \n",
//                   node_buff, pop_node->comp_counters[0], pop_node->total_stat, inclusion_flag);
//        }

        if (tmpindex < min_k && pop_node->total_stat > thresh && inclusion_flag) {
            //printf(" pop_node total stat added\n");
            tmpindex++;
            total_pop += pop_node->total_stat;
            //printf("<><><><>&&&&&&&&&&&&&&&&comp_counters 0 is : %lu \n",pop_node->comp_counters[0]);
            tree_node  *cur_par = pop_node->parent;

            while (cur_par != NULL  && !node_equals(cur_par, start_node, m)) {
                cur_par->total_stat -= pop_node->total_stat;
                cur_par = cur_par->parent;
            }
        } else if (tmpindex >= min_k) break;
        tree_node *tmp_parent = pop_node;

        tree_node * parent = pop_node->parent;
        if (parent) {
            parent->stats->done_stat++;
            if(parent->stats->done_stat == parent->stats->cson_stat){
                pq_push(priority_queue, pop_node->parent->total_stat, (void *) (pop_node->parent));
            }
        }
    }
    free(priority_queue);
    return total_pop;

}

int create_inclusive_tree(char* search_str, ft_config_t *dst_config, ft_config_t *src_config){
    MODE  m = dst_config->mode;
    uint32_t rf[DIM * 2];
    create_flow_from_tree_file(&search_str, rf, m);
    tree_node *search_node = create_tree_node_from_flow(rf, m);

    tree_node **src_hash_tbl = &src_config->TREE;
    tree_node **dst_hash_tbl = &dst_config->TREE;
    tree_node *src_node , *tmp_src;
    uint32_t * src_flow_key = NULL;
    HASH_ITER(hh, *src_hash_tbl, src_node , tmp_src){
        src_flow_key = src_node->flow_key;

        if (check_include_flow_key(src_node->flow_key,search_node->flow_key,m))
            update_or_create_add_node(src_node, dst_config);
    }
    return 0;
}
void update_or_create_add_node(tree_node *src_node, ft_config_t *dst_config) {
    MODE m = dst_config->mode;
    tree_node **flow1 = &dst_config->TREE;
    tree_node *node_to_update = NULL, *flow1_node;
    node_to_update = get_flow_hmap_((const tree_node **) dst_config, src_node->flow_key, m);
    if (node_to_update) {
        ADD_COMP_COUNTERS(node_to_update->comp_counters, src_node->comp_counters, 6);
    } else {
        add_tree_node(src_node->flow_key, 0, src_node->comp_counters, 6, dst_config);
        flow1_node = get_flow_hmap_((const tree_node **) flow1, src_node->flow_key, m);
        COPY_COMP_COUNTERS(flow1_node->comp_counters, src_node->comp_counters, 6);
    }
}

int check_inclusion_and_subnode_flowstr(char* node_flowstr, char *subnode_flowstr, MODE m){

    uint32_t node_key[DIM*2];
    convert_flowstr_to_flowkey_considering_any(&node_flowstr,node_key,m);
//    printf("The search_node's flowkey is : %lu %lu %lu %lu\n",node_key[0],node_key[1],node_key[2],node_key[3]);
    uint32_t subnode_key[DIM*2];
    convert_flowstr_to_flowkey_considering_any(&subnode_flowstr,subnode_key,m);
//    printf("The node's flowkey is : %lu %lu %lu %lu\n",subnode_key[0],subnode_key[1],subnode_key[2],subnode_key[3]);

    mask_idx idxs = MASK_IDXs[m];
    int i;
    for(i = 0 ; i < DIM; i++){
        int ip_or_port = idxs.idx[i];
        const uint32_t *mask_list = MASK_TABLE[ip_or_port];
        /** if 256 meaning if ANY **/
        if(!( (*(node_key +i) == (*(subnode_key +i) & mask_list[(*(node_key+i+DIM))])) && (*(node_key +i+DIM) <= *(subnode_key + i + DIM)) ))
            return 0 ;
    }
    return 1;
}
int convert_flowstr_to_flowkey_considering_any(char **flow_str, uint32_t *flow_key, MODE m) {
    const mask_idx idxs = MASK_IDXs[m];
    int i, fields, buff2_index = 0;
    char *buff[DIM];
    char *buff2[DIM * 2];
    fields = split(buff, flow_str, ",");

    if (fields < DIM) {
        printf("num_fields are %d, dims is %d mode is %d\n", fields, DIM, m);
        log_fatal("create_flow_from_tree_file: splitting flow failed\n");
        exit(-1);
    }
    for (int j = 0; j < fields; j++) {
        if (strcmp(buff[j],"ANY") == 0) {
            buff2[buff2_index] = "0";
            buff2[buff2_index + 1] = "0";
        } else{
            split(&buff2[buff2_index], &buff[j], "|");
        }
        buff2_index += 2;

    }
    for (i = 0; i < DIM; i++) {
        int ip_pref_char_indx = 2 * i + 1;
        int ip_char_indx = 2 * i;
        int ip_or_port = idxs.idx[i];
        uint32_t *mask_list = MASK_TABLE[ip_or_port];
        sscanf(buff2[ip_pref_char_indx], "%u", &flow_key[i + DIM]);

        if (!ip_or_port) {
            flow_key[i] = (ip4_str_int_le(buff2[ip_char_indx]) & mask_list[flow_key[i + DIM]]);
        } else {
            flow_key[i] = (str_to_le_int32(buff2[ip_char_indx]) & mask_list[flow_key[i + DIM]]);
        }
    }
    return 0;
}