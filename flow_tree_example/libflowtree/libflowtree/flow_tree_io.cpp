#include "flow_tree_io.hpp"
#include <sys/mman.h>
void serialize_tree_node_optimized(tree_node * node,char * buffer, MODE m, int counter_type);

size_t NODE_BLOB_SIZE_CT_0[11]={6*sizeof(uint32_t)+6*sizeof(uint64_t),
			   6*sizeof(uint32_t)+6*sizeof(uint64_t),
			   6*sizeof(uint32_t)+6*sizeof(uint64_t),
			   6*sizeof(uint32_t)+6*sizeof(uint64_t),
			   6*sizeof(uint32_t)+6*sizeof(uint64_t),
			   6*sizeof(uint32_t)+6*sizeof(uint64_t),
			   4*sizeof(uint32_t)+6*sizeof(uint64_t),
			   4*sizeof(uint32_t)+6*sizeof(uint64_t),
			   4*sizeof(uint32_t)+6*sizeof(uint64_t),
			   4*sizeof(uint32_t)+6*sizeof(uint64_t),
			   10*sizeof(uint32_t)+6*sizeof(uint64_t)};

size_t NODE_BLOB_SIZE_CT_1[11]={6*sizeof(uint32_t)+6*sizeof(uint32_t),
			   6*sizeof(uint32_t)+6*sizeof(uint32_t),
			   6*sizeof(uint32_t)+6*sizeof(uint32_t),
			   6*sizeof(uint32_t)+6*sizeof(uint32_t),
			   6*sizeof(uint32_t)+6*sizeof(uint32_t),
			   6*sizeof(uint32_t)+6*sizeof(uint32_t),
			   4*sizeof(uint32_t)+6*sizeof(uint32_t),
			   4*sizeof(uint32_t)+6*sizeof(uint32_t),
			   4*sizeof(uint32_t)+6*sizeof(uint32_t),
			   4*sizeof(uint32_t)+6*sizeof(uint32_t),
			   10*sizeof(uint32_t)+6*sizeof(uint32_t)};

size_t NODE_BLOB_SIZE_CT_2[11]={6*sizeof(uint32_t)+6*sizeof(uint16_t),
			   6*sizeof(uint32_t)+6*sizeof(uint16_t),
			   6*sizeof(uint32_t)+6*sizeof(uint16_t),
			   6*sizeof(uint32_t)+6*sizeof(uint16_t),
			   6*sizeof(uint32_t)+6*sizeof(uint16_t),
			   6*sizeof(uint32_t)+6*sizeof(uint16_t),
			   4*sizeof(uint32_t)+6*sizeof(uint16_t),
			   4*sizeof(uint32_t)+6*sizeof(uint16_t),
			   4*sizeof(uint32_t)+6*sizeof(uint16_t),
			   4*sizeof(uint32_t)+6*sizeof(uint16_t),
			   10*sizeof(uint32_t)+6*sizeof(uint16_t)};




void read_tree_from_file(char *tree_file, tree_node **TREE, MODE m) {
    FILE *file_ptr;
    file_ptr = fopen(tree_file, "r");
    if (!file_ptr)
        return;
    char buff[131070];
    while (fgets(buff, sizeof(buff), file_ptr)) {
        char *tmp = (char *) buff;
        int field;
        char *tokens[2048];
        field = split(tokens, &tmp, "-");
        if (field > 0) {
            if (strlen(tokens[0])) {
                uint32_t flow_key[DIM * 2];
                memset(flow_key, 0, MODE_SIZES[m]);
                create_flow_from_tree_file((char **) &tokens[0], flow_key, m);
                tree_node *node = NULL;
                node = get_flow_hmap_((const tree_node **) TREE, (const uint32_t *) flow_key, m);
                if (!node) {
                    node = create_tree_node_from_flow(flow_key, m);
                    add_node_hmap((tree_node **) TREE, node, m);
                }
                uint64_t total = 0;
		for(int i = 0 ; i < 6 ; i++){
		  if (strlen(tokens[i+1])) {
                    sscanf(tokens[i+1], "%lu", &node->comp_counters[i]);
		  }		  
		}
                if (strlen(tokens[7])) {
                    sscanf(tokens[7], "%lu", &total);
                }
                node->total_stat = total;
                if (strlen(tokens[8])) {
                    uint32_t parent_flow[DIM * 2];
                    memset(parent_flow, 0, MODE_SIZES[m]);
                    create_flow_from_tree_file((char **) &tokens[8], parent_flow, m);
                    tree_node *parent_node = NULL;
                    //	       if(flow_in_hmap((const tree_node **)TREE, (const uint32_t *)parent_flow.flow_key)){
                    parent_node = get_flow_hmap_((const tree_node **) TREE, (const uint32_t *) parent_flow, m);
                    if (!parent_node) {
                        parent_node = create_tree_node_from_flow(parent_flow, m);
                        add_node_hmap((tree_node **) TREE, parent_node, m);
                    }
                    node->parent = parent_node;
                    if (!check_node_in_sons(node, parent_node, m)) {
                        add_to_children(node, parent_node);
                        //printf("added to children %d\n",utarray_len(parent_node->children));
                    }
                } else {
		  //log_trace("parent not present %s\n", buff);

                }
            }
        } else {

        }
    }
}
void read_tree_from_bin_file(char *tree_file, ft_config_t *conf){
  FILE *file_ptr = NULL;
  file_ptr = fopen(tree_file, "r");
  if(!file_ptr) return;
  flow_tree_meta meta;
  tree_node **TREE = &conf->TREE;
  size_t n = 0;
  n = fread(&meta,1,sizeof(flow_tree_meta),file_ptr);
  if( n < sizeof(flow_tree_meta)) return; //goto fail;  
  //  printf("number of nodes in the flow_tree is %lu\n", meta.tree_node_num);
  MODE m = INT_TO_MODE[meta.tree_mode];
  conf->mode = m;
  conf->granularity = meta.granularity;
  conf->timestamp = meta.time_stamp;
  conf->site_id = meta.site_id; 
  uint32_t element_size = MODE_SIZES[m]*2 + sizeof(uint64_t)*6;
  char *buff,*curr_buff = NULL;  
  buff = (char *)calloc(meta.tree_node_num,element_size);
  curr_buff = buff; 
  n = fread(buff,1,meta.tree_node_num*element_size,file_ptr);
  for(uint32_t i = 0 ; i < meta.tree_node_num; i++){
    uint32_t *flow_key = (uint32_t *)curr_buff;
    tree_node *node = NULL;
    node = get_flow_hmap_((const tree_node **) TREE, (const uint32_t *)flow_key, m);
    if(!node){
      node = create_tree_node_from_flow(flow_key, m);
      add_node_hmap((tree_node **) TREE, node, m); 
    }
    curr_buff += MODE_SIZES[m];
    memcpy( &node->comp_counters[0],curr_buff, 6*sizeof(uint64_t));
    curr_buff += (6*sizeof(uint64_t));
    //memcpy( &node->total_stat,curr_buff, sizeof(uint64_t));
    //curr_buff += sizeof(uint64_t);
    uint32_t *parent_flow = (uint32_t *) curr_buff; 
    if( !flowkey_equals(flow_key, parent_flow, m)){
      tree_node *parent_node = NULL;
      parent_node = get_flow_hmap_((const tree_node **) TREE, (const uint32_t *) parent_flow, m);
      if (!parent_node) {
	parent_node = create_tree_node_from_flow(parent_flow, m);
	add_node_hmap((tree_node **) TREE, parent_node, m);
      }
      node->parent = parent_node;
      if (!check_node_in_sons(node, parent_node, m)) {
	add_to_children(node, parent_node);	
      }
    }else{
      node->parent = NULL;
    }
    curr_buff += MODE_SIZES[m];        
  }

  if(n < element_size * meta.tree_node_num)
    {
      //  printf("the n is %lu\n",n);
      return;
      //goto fail;
    }
  fclose(file_ptr);
  if(buff) free(buff);
  return;

}

uint32_t get_element_size_from_meta(flow_tree_meta * meta){
  int m = meta->tree_mode;
  switch(meta->counter_type){
  case 0:
    return NODE_BLOB_SIZE_CT_0[m];
  case 1:
    return NODE_BLOB_SIZE_CT_1[m];
  case 2:
    return NODE_BLOB_SIZE_CT_2[m];
  default:
    return  NODE_BLOB_SIZE_CT_0[m];

  }
}

void copy_counters_to_node32(tree_node *node, char *curr_buff){
  uint32_t casted_counters[6] ;
  memcpy(&casted_counters, curr_buff, 6*sizeof(uint32_t));
  for(int i = 0 ; i < 6 ; i++){
    node->comp_counters[i]=casted_counters[i];
  }
}
void copy_counters_to_node16(tree_node *node, char *curr_buff){
  uint16_t casted_counters[6] ;
  memcpy(&casted_counters, curr_buff, 6*sizeof(uint16_t));
  for(int i = 0 ; i < 6 ; i++){  
    node->comp_counters[i]=casted_counters[i];
  }
}

void read_optimized_tree_from_bin_file(char *tree_file, ft_config_t *conf){
  FILE *file_ptr = NULL;
  file_ptr = fopen(tree_file, "r");
  if(!file_ptr) return;
  flow_tree_meta meta;
  tree_node **TREE = &conf->TREE;
  size_t n = 0;
  n = fread(&meta,1,sizeof(flow_tree_meta),file_ptr);
  if( n < sizeof(flow_tree_meta)) return; //goto fail;  
  //  printf("number of nodes in the flow_tree is %lu\n", meta.tree_node_num);
  MODE m = INT_TO_MODE[meta.tree_mode];
  conf->mode = m;
  conf->granularity = meta.granularity;
  conf->timestamp = meta.time_stamp;
  conf->site_id = meta.site_id;
  uint32_t element_size = get_element_size_from_meta(&meta);  
  uint8_t* buff = NULL;
  buff = (uint8_t *)calloc(meta.tree_node_num,element_size);
  tree_node **mini_keys =(tree_node **) calloc( meta.tree_node_num,sizeof(tree_node *)) ;
  tree_node *nodes[meta.tree_node_num]; 
  n = fread(buff,1,meta.tree_node_num*element_size,file_ptr);  
  for(uint32_t i = 0 ; i < meta.tree_node_num; i++){
    nodes[i]= (tree_node *)calloc(1,sizeof(tree_node));
    init_node(nodes[i]); 
    mini_keys[i] = nodes[i]; 
  }
  
  char *curr_buff = (char *)buff;
  for(uint32_t i = 0 ; i < meta.tree_node_num; i++){
    uint32_t *flow_key = (uint32_t *)curr_buff;
    tree_node *node = NULL;    
    uint32_t *f_key = (uint32_t *)calloc(1,DIM*2*sizeof(uint32_t));        
    for(int j  = 0 ; j<DIM ; j++ )
      {
    	f_key[j]=flow_key[j];
    	f_key[j+DIM]=flow_key[j+DIM];
      }
    curr_buff += MODE_SIZES[m];
    uint32_t mini_key = 0;
    memcpy(&mini_key, curr_buff, sizeof(uint32_t));
    node = mini_keys[mini_key];    
    node->flow_key = f_key; 
    node->total_stat = mini_key;
    curr_buff += sizeof(uint32_t); 
    add_node_hmap((tree_node **) TREE, node, m); 
    if(node->flow_key[DIM]!=0){
      uint32_t parent_key = 0;//*curr_buff;
      memcpy(&parent_key, curr_buff, sizeof(uint32_t));
      tree_node *parent = mini_keys[parent_key];
      node->parent = parent;
      if(!check_node_in_sons(node,parent,m)){
	add_to_children(node,parent);
      }
    }else{
      conf->root = node; 
    }
    curr_buff+= sizeof(uint32_t);

    switch(meta.counter_type){
    case 0:
      memcpy(node->comp_counters, curr_buff, 6*sizeof(uint64_t));
      curr_buff += (6*sizeof(uint64_t));
      break;
    case 1:
      copy_counters_to_node32(node, curr_buff);
      curr_buff += (6 * sizeof(uint32_t));
      break;
    case 2:
      copy_counters_to_node16(node, curr_buff);
      curr_buff += (6 *sizeof(uint16_t));
      break;
    default:
      memcpy(node->comp_counters, curr_buff, 6*sizeof(uint64_t));
      curr_buff += (6*sizeof(uint64_t));
      break;
    }

  }

  if(n < element_size * meta.tree_node_num)
    {
      //  printf("the n is %lu\n",n);
      return;
      //goto fail;
    }
  fclose(file_ptr);
  if(buff) free(buff);
  if(mini_keys) free(mini_keys); 
  return;
  // fail:
  //if(file_ptr) fclose(file_ptr);
  //if(buff) free(buff);
  //fprintf(stderr,"failed to read binary flow_tree file\n");
}
void output_flow_tree_bin(char *output_file_name, ft_config_t *conf, flow_tree_meta * meta){
  FILE *f;
  tree_node **TREE = &conf->TREE;
  tree_node *current_node, *tmp;
  MODE m = conf->mode;
  f = fopen(output_file_name, "w");
  char *buff = NULL;
  if(f){  
    //buffer_size is two times of the flow_key size + size of pop and comp_pop
    uint32_t element_size = MODE_SIZES[m] * 2 + sizeof(uint64_t) * 6;  
    buff = (char *)calloc(meta->tree_node_num, element_size);
    uint32_t buff_size = meta->tree_node_num*element_size;
    char * curr_buff = buff; 
    uint32_t buff_idx = 0 ; 
    //copy the nodes into the buffer
    HASH_ITER(hh, *TREE, current_node, tmp){    
      memcpy(curr_buff, current_node->flow_key,MODE_SIZES[m]);
      curr_buff += MODE_SIZES[m];    
      memcpy(curr_buff, &current_node->comp_counters[0],(6*sizeof(uint64_t)));
      curr_buff += (6*sizeof(uint64_t));      
      if(current_node->parent) memcpy(curr_buff, current_node->parent->flow_key,MODE_SIZES[m]);
      curr_buff += MODE_SIZES[m]; 
    }
    fwrite(meta,sizeof(flow_tree_meta),1,f);
    fwrite(buff, 1,buff_size, f);
    fclose(f);
  }
  if(buff){
    free(buff);
  }
}

void copy_counters32(tree_node *node, char *buffer){
  uint32_t casted_value[6] ;
  for(int i = 0 ; i < 6 ; i++){    
    casted_value[i] = (uint32_t)node->comp_counters[i];
  }
  memcpy(buffer, &casted_value, 6*sizeof(uint32_t));
}

void copy_counters16(tree_node *node, char *buffer){
  uint16_t casted_values[6];
  for(int i = 0 ; i < 6 ; i++){
     casted_values[i] = (uint16_t)node->comp_counters[i];
  }
    memcpy(buffer, &casted_values, 6*sizeof(uint16_t));


}
void serialize_tree_node_optimized(tree_node * node,char * buffer, MODE m, int counter_type){
  uint32_t *key_buff=(uint32_t *)buffer;
  memcpy(buffer,node->flow_key,MODE_SIZES[m]);
  buffer+= MODE_SIZES[m];
  uint32_t mini_key = (uint32_t)node->total_stat;
  memcpy(buffer,&mini_key,sizeof(uint32_t));
  buffer+=sizeof(uint32_t);
  if(node->parent) {
    uint32_t parent_mini_key = node->parent->total_stat;
    memcpy(buffer,&parent_mini_key,sizeof(uint32_t));
  }
  buffer+=sizeof(uint32_t);
  switch(counter_type){
  case 0: 
    memcpy(buffer, &node->comp_counters, sizeof(uint64_t) * 6 );
    break;
  case 1:
    copy_counters32(node, buffer);
    break;
  case 2:
    copy_counters16(node, buffer);
    break;
  default:
    memcpy(key_buff, &node->comp_counters, sizeof(uint64_t) * 6 );
    break;
  }
  
}

void output_flow_tree_bin_optimized(char *output_file_name, ft_config_t *conf, flow_tree_meta * meta){
  FILE *f;
  tree_node **TREE = &conf->TREE;
  MODE m = conf->mode;
  cout << "outputed tree mode is " << m << endl;
  f = fopen(output_file_name, "w");
  char *buff = NULL;
  tree_node ** mini_keys = NULL;
  if(f){
    uint32_t tree_size = meta->tree_node_num;
    int counter_type = meta->counter_type; 
    uint32_t element_size = get_element_size_from_meta(meta); 
    buff = (char *)calloc(tree_size, element_size);
    uint32_t buff_size = tree_size*element_size;
    uint32_t i = 0, j = 0;
    mini_keys = (tree_node **)calloc(tree_size, sizeof(tree_node *));
    uint32_t buff_index = 0; 
    uint32_t iter = 0; 
    tree_node *cur_node, *tmp;
    HASH_ITER(hh, *TREE, cur_node, tmp) {
      mini_keys[iter]=cur_node;
      cur_node->total_stat = iter;
      iter++;
    }
    cur_node = NULL;
    tmp = NULL;    
    char *cur_buff = buff;     
    for(i = 0; i < tree_size ; i++){
      cur_node = mini_keys[i];      
      serialize_tree_node_optimized(cur_node,cur_buff,m, counter_type);
      cur_buff+=element_size;
    }      
    //copy the nodes into the buffer
    fwrite(meta,sizeof(flow_tree_meta),1,f);
    fwrite(buff, 1,buff_size, f);
    compress_to_target(conf, tree_size);
    fclose(f);
  }
  if(buff) free(buff);  
  if(mini_keys) free(mini_keys); 
}

void output_tree_file(char *file_name, tree_node **TREE, MODE m) {
    FILE *fp = NULL;
    UT_array *COUNT_LEAF;
    UT_array *COUNT_INTERIOR;
    utarray_new(COUNT_LEAF, &flowkey_icd);
    utarray_new(COUNT_INTERIOR, &flowkey_icd);
    fp = fopen(file_name, "w");
    compute_cur_count(TREE, COUNT_LEAF, COUNT_INTERIOR, m);
    tree_node *current_node, *tmp;
    if (fp) {
        HASH_ITER(hh, *TREE, current_node, tmp) {
            char buff[131070];
            node_to_string_full(current_node, buff, 131070, TREE, m);
            fprintf(fp, "%s-tree\n", buff);
            if (current_node->stats) {
                free(current_node->stats);
                current_node->stats = NULL;
            }
        }
        fclose(fp);
    } else {
        log_warn("could not open tree_file\n");
    }
    utarray_free(COUNT_INTERIOR);
    utarray_free(COUNT_LEAF);
}

void output_result_file(char *file_name, char *str, ft_config_t *conf) {
    tree_node *current_node, *tmp;
    tree_node **TREE = &conf->TREE;
    MODE m = conf->mode;
    FILE *fp = NULL;
    uint32_t tree_entries = count_hmap(TREE);
    fp = fopen(file_name, "w");
    if (fp) {
        fprintf(fp, "Output_result %lu: %s entries %u hashes %lu tree %lu/%lu mem %lu (%lu)\n", conf->n, str,
                tree_entries, conf->hash_count, conf->tree_add, conf->tree_delete, conf->mem, conf->mem_exceeded);
        HASH_ITER(hh, *TREE, current_node, tmp) {
            char buff[2048];
            node_to_string_compact(current_node, buff, m);
            fprintf(fp, "%s %lu %lu %s\n", buff, current_node->comp_pop, current_node->total_stat, str);
        }
        fclose(fp);
    } else {
        log_warn("could not open tree_file\n");
    }

}
int parse_mac_to_site_map(char * macs,  map<string, uint32_t> &mac_to_site_map, int file_type){
  string mac(macs);
  std::vector<std::string> mac_site_id_pair_vector;
  boost::split(mac_site_id_pair_vector, mac, boost::is_any_of(","));
  uint16_t v_length = mac_site_id_pair_vector.size();
  if(v_length % 2 != 0) return (EXIT_FAILURE);
  int mac_pair_idx = 0;
  for(mac_pair_idx = 0 ; mac_pair_idx < v_length; mac_pair_idx+=2){
    string mac_str = mac_site_id_pair_vector[mac_pair_idx];
    string site_id_str = mac_site_id_pair_vector[mac_pair_idx+1];
    uint32_t site_id;
    //convert site_id_str to uint32_t 
    std::stringstream site_id_stream;
    site_id_stream << site_id_str;
    site_id_stream >> site_id;    
    //convert mac strings to bytes 
    if(file_type == INPUT_TYPE_PCAP){
      std::vector<std::string> mac_parts;
      boost::split(mac_parts, mac_str, boost::is_any_of("-"));
      unsigned char mac_bytes[ETHER_ADDR_LEN] ;
      int k = 0;
      for(auto j : mac_parts){
	std::stringstream ss;
	ss << std::hex << j;
	unsigned int character ;
	ss >> character;
	mac_bytes[k] = (unsigned char)character;
	k++;
      }
      string mac_pcaped((char *)mac_bytes, ETHER_ADDR_LEN);
      mac_to_site_map[mac_pcaped] = site_id;
    }else{
      mac_to_site_map[mac_str] = site_id; 
    }
						  
  }
  return 0;
}
void init_site_stats_map(map<string, site_stats> & site_stats_map, map<std::string , uint32_t>& mac_to_site){
  for(map<string , uint32_t>::iterator it = mac_to_site.begin(); it!=mac_to_site.end(); ++it){
    uint32_t buffer_size_pkt = 1000000; 
    uint32_t packets_read = 0 ;  
    site_stats stat ;
    stat.site_id = it->second; 
    stat.site_buffer  = (char *)calloc(buffer_size_pkt*sizeof(packet_bin),sizeof(char));
    stat.buffer_size_pkt = buffer_size_pkt;
    stat.packets_read = 0 ;
    stat.buffer_sizes = (uint64_t)(buffer_size_pkt*sizeof(packet_bin));
    site_stats_map[it->first] = stat; 
  }

}
void fix_buffer_sizes(map<string, site_stats>& site_stats_map, map<uint32_t , char *>& site_buffers, map<uint32_t, uint64_t>& site_buffer_sizes){
  for(map<string, site_stats>::iterator it = site_stats_map.begin(); it!=site_stats_map.end(); ++it){
    site_stats st = it->second;
    uint32_t site_id = st.site_id;
    //    printf("fixing ... %lu-read_packets: %lu\n", st.site_id, st.packets_read);
      if(st.packets_read != st.buffer_size_pkt){
	char *buffer = st.site_buffer;
	buffer = (char *)realloc(buffer, st.packets_read*sizeof(packet_bin));
	st.site_buffer = buffer;
      }
      site_buffers[site_id] = st.site_buffer;      
      site_buffer_sizes[site_id] = st.packets_read * sizeof(packet_bin);      
      char *buff_for_advise = st.site_buffer;
      madvise(buff_for_advise, st.packets_read*sizeof(packet_bin), MADV_HUGEPAGE | MADV_SEQUENTIAL);
  }
}
int pcap_file_to_buffers(char *path_to_workload,  map<std::string , uint32_t>& mac_to_site, map<uint32_t , char *>& site_buffers, map<uint32_t, uint64_t>& site_buffer_sizes, uint32_t granularity){
  long int trace_start = 0 ; 
  struct pcap_pkthdr header;// The header that pcap gives us
  const u_char *packet;
  const struct struct_ethernet *ethernet;
  double msec_to_sec = pow(10.0, 6.0);
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];// not sure what to do with this, oh well
  const char *file_name = path_to_workload;
  handle = pcap_open_offline(file_name, errbuf);// call pcap library function
  if(handle == NULL){
    printf("%s\n",errbuf);
    return (EXIT_FAILURE);
  }
  uint64_t num_pkt = 0; 
  map<string , site_stats> site_stats_map;
  init_site_stats_map(site_stats_map, mac_to_site);

  while ((packet = pcap_next(handle, &header))) {
    u_char *pkt_ptr = (u_char *) packet;
    int ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13];
    int ether_offset = 0;
    if (ether_type == ETHER_TYPE_IP)// most common
      ether_offset = 14;
    else if (ether_type == ETHER_TYPE_8021Q)// my traces have this
      ether_offset = 18;
    else
      continue;
    ethernet = (struct struct_ethernet *)(pkt_ptr);
    const char * values = (char *)ethernet->ether_shost;
    string src_mac((char *)ethernet->ether_shost, ETHER_ADDR_LEN);
    pkt_ptr += ether_offset;// skip past the Ethernet II header
    struct ip *ip_hdr = (struct ip *)pkt_ptr;// point to an IP header structure
    int packet_length = ntohs(ip_hdr->ip_len);
    int ip_protocol = ip_hdr->ip_p;// whould be 0x11 = UDP
    int ip_version = ip_hdr->ip_v;// should be ?
    if ((ip_version == 4) && ((ip_protocol == 0x11) || (ip_protocol == 0x6))) {
      if(site_stats_map.find(src_mac)!= site_stats_map.end()){

	site_stats site_stat = (site_stats_map.find(src_mac))->second;
	uint32_t buffer_size_pkt = site_stat.buffer_size_pkt; 
	uint32_t packets_read = site_stat.packets_read;
	char *buffer = site_stat.site_buffer;
	if(packets_read >= buffer_size_pkt){
	  buffer_size_pkt += buffer_size_pkt; 
	  buffer = (char *)realloc(buffer,buffer_size_pkt*sizeof(packet_bin));
	  site_stat.site_buffer = buffer;
	  site_stat.buffer_size_pkt = buffer_size_pkt;

	}
	packet_bin * buffer_in_pkt = (packet_bin *)buffer;
	buffer_in_pkt += packets_read; 
	long int second = header.ts.tv_sec;
	if(trace_start == 0 )
	  trace_start = second;
	if(second >= trace_start + 60*granularity)
	  break;
	long int micro_second = header.ts.tv_usec;
	double m_sec_double = (double)micro_second/msec_to_sec;
	double sec_double = (double)second;
	double ts = sec_double+m_sec_double; 
	buffer_in_pkt->ts = ts;
	buffer_in_pkt->values[0] = (uint32_t)ntohl(ip_hdr->ip_src.s_addr);
	buffer_in_pkt->values[1] = (uint32_t)ntohl(ip_hdr->ip_dst.s_addr);

	int offset = 20;
	uint32_t byte_count = (uint32_t)header.len;

	pkt_ptr += offset;// skip past the Ethernet II header
	if(ip_protocol == 0x11){
	  buffer_in_pkt->proto = 17;
	  buffer_in_pkt->packet_count[0] = 1;
	  buffer_in_pkt->packet_count[2] = byte_count;

        struct udphdr *udp_hdr = (struct udphdr *)(pkt_ptr);
	  int udp_src_port = ntohs(udp_hdr->source);
	  int udp_dst_port = ntohs(udp_hdr->dest);
	  buffer_in_pkt->values[2] = (uint32_t) udp_src_port;
	  buffer_in_pkt->values[3] = (uint32_t) udp_dst_port;
	}else{
	  buffer_in_pkt->proto = 6;
	  buffer_in_pkt->packet_count[0] = 1;
	  buffer_in_pkt->packet_count[2] = byte_count;

        struct tcphdr *tcp_hdr = (struct tcphdr *)(pkt_ptr);
	  int tcp_src_port = ntohs(tcp_hdr->th_sport);
	  int tcp_dst_port = ntohs(tcp_hdr->th_dport);
	  buffer_in_pkt->values[2] = (uint32_t)tcp_src_port;
	  buffer_in_pkt->values[3] = (uint32_t)tcp_dst_port;	 
	}
	packets_read++;
	site_stat.packets_read = packets_read;
	site_stats_map[src_mac] = site_stat;
      }
    }
  }
  // printf("fixing buffer sizes\n");
  fix_buffer_sizes(site_stats_map, site_buffers, site_buffer_sizes);
  return 0;
}
int str_pipe_to_buffers(map<string, uint32_t> &mac_to_site, map<uint32_t , char *>& site_buffers, map<uint32_t, uint64_t>& site_buffer_sizes, uint32_t granularity, FILE *handle, int *handle_done){
  char buff[1024];
  char *tokens[100] ;
  uint64_t trace_start = 0 ;
  uint64_t num_read_pkts = 0 ;
  map<string , site_stats> site_stats_map;
  init_site_stats_map(site_stats_map, mac_to_site);
  //TODO: use mmap instead of fgets and fopen? read until we reach the granularity
  *handle_done = 1;
  cout << "starting reading the workload" << endl;
  while(fgets(buff, sizeof(buff), handle)!=NULL){
    char *tmp = (char *)buff;
    //printf( "output from ipf_fix parser %s\n" ,buff);
    split(tokens, &tmp, " ");
    //printf( "output from ipf_fix strlen is %s\n", (char *)tokens[SRC_MAC_INDEX]);
    string src_mac((char *)tokens[SRC_MAC_INDEX]);
    boost::trim(src_mac);
    //src_mac = "all";
    num_read_pkts++ ;

      if(site_stats_map.find(src_mac)!=site_stats_map.end()){
      site_stats site_stat = (site_stats_map.find(src_mac))->second;
      uint32_t buffer_size_pkt = site_stat.buffer_size_pkt;
      uint32_t packets_read = site_stat.packets_read;
      char *buffer = site_stat.site_buffer;
      if(packets_read >= buffer_size_pkt){
	buffer_size_pkt += buffer_size_pkt;
	buffer = (char *)realloc(buffer,buffer_size_pkt*sizeof(packet_bin));
	site_stat.site_buffer = buffer;
	site_stat.buffer_size_pkt = buffer_size_pkt;
      }
      packet_bin * buffer_in_pkt = (packet_bin *)buffer;
      buffer_in_pkt += packets_read;
      double time;
      sscanf(tokens[0], "%lf", &time);
      uint64_t time_int = (uint64_t)time;
      if(trace_start == 0 )
	    trace_start = time_int;
      if(time_int >= trace_start + 60*granularity){
          *handle_done = 0;
          cout << "stoped reading the handle" << time_int << " " << granularity << " " << trace_start << " " << num_read_pkts <<   endl;
          break;
      }
      buffer_in_pkt->ts = time;
      uint32_t src_ip = ip4_str_int_le(tokens[1]);
      uint32_t dst_ip = ip4_str_int_le(tokens[2]);
      uint32_t src_port = str_to_le_int32(tokens[3]);
      uint32_t dst_port = str_to_le_int32(tokens[4]);
      uint8_t proto = 6;
      if(strcmp(tokens[5],"17"))
	{
	  proto = 17;
	}
      //uint8_t proto = (uint8_t)atoi(tokens[5]);
      uint64_t counter = str_to_le_int32(tokens[6]);
      //uint64_t counter = 1;
      buffer_in_pkt->values[0] = src_ip;
      buffer_in_pkt->values[1] = dst_ip;
      buffer_in_pkt->values[2] = src_port;
      buffer_in_pkt->values[3] = dst_port;
      buffer_in_pkt->proto = proto;
      buffer_in_pkt->packet_count[0] = counter;
      if(strlen(tokens[8])) buffer_in_pkt->packet_count[1] = str_to_le_int32(tokens[8]);
      buffer_in_pkt->packet_count[2] = 1;
      packets_read++;
      site_stat.packets_read = packets_read;
      site_stats_map[src_mac] = site_stat;
    }
  }
  fix_buffer_sizes(site_stats_map, site_buffers, site_buffer_sizes);
  return 0 ;
}

int output_packet_bin(ft_config_t *config, map<string, uint32_t> &mac_to_site_map, map<uint32_t , char *>& site_buffers, map<uint32_t, uint64_t>& site_buffer_sizes){
  //  printf("outputing ... %lu\n", site_buffers.size());
  std::pair<uint32_t, char *> p;
  BOOST_FOREACH(p, site_buffers) {
                  //printf("outputing iterating in buffers ...\n");
                  uint32_t site_id = p.first;
                  char *buffer = (char *) p.second;
                  uint64_t buffer_size = 0;
                  //Generate a unique file name
                  if (buffer) {
                      double buffer_time_stamp = *((double *) buffer);
                      //Prepare file meta data (reusing the flow_tree_meta)
                      flow_tree_meta ft_meta;
                      ft_meta.granularity = config->granularity;
                      ft_meta.time_stamp = (uint64_t) buffer_time_stamp;
                      ft_meta.site_id = site_id;
                      if (site_buffer_sizes.find(site_id) != site_buffer_sizes.end()) {
                          buffer_size = site_buffer_sizes.find(site_id)->second;
                      } else {
                          fprintf(stderr, "something weird in the sizes and output_packet_bin\n");
                          return EXIT_FAILURE;
                      }

                      ft_meta.tree_node_num = buffer_size / sizeof(packet_bin);
                      string output_file_name = string(config->out_path) + "/" + string(config->pkt_file) + "." +
                                                to_string(site_id) + "." + to_string(config->granularity) + "." +
                                                to_string(buffer_time_stamp) +"." + to_string(ft_meta.tree_node_num) + ".packet.bin";
                      cout << output_file_name << endl;

                      FILE *output_file = NULL;
                      output_file = fopen(output_file_name.c_str(), "w");
                      if (output_file) {
                          fwrite(&ft_meta, sizeof(flow_tree_meta), 1, output_file);
                          fwrite(buffer, 1, buffer_size, output_file);
                          fclose(output_file);
                      }
                  }
              }
  return 0;

}
int read_packet_bin_file(char *file_name, char **buffer, uint64_t *buffer_size, ft_config_t *config){
  FILE *file_ptr = NULL;
  char *f_name = file_name; 
  if(f_name == NULL){
    string input_file= string(config->data_path) + "/"+string(config->pkt_file);
    f_name = (char *)input_file.c_str();
  }
  file_ptr = fopen(f_name, "r");
  if(!file_ptr) return -1;
  flow_tree_meta meta;
  size_t n = 0;
  n = fread(&meta,1,sizeof(flow_tree_meta),file_ptr);
  config->site_id = meta.site_id;  
  char *buff = NULL;
  buff = (char *) calloc(meta.tree_node_num, sizeof(packet_bin));  
  n = fread(buff,1,meta.tree_node_num * sizeof(packet_bin),file_ptr);
  *buffer_size = (meta.tree_node_num * sizeof(packet_bin)); 
  *buffer = buff; 
  fclose(file_ptr);
  return 0;

}
