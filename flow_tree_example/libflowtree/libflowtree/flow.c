#include "flow.h"

extern inline int flowkey_equals(uint32_t *node1, uint32_t *node2, MODE m);

extern inline int check_include_flow_key(uint32_t *node_key, uint32_t *subnode_key, MODE m);

extern inline int is_leaf_flow(uint32_t *flow_key, MODE m);

extern inline int create_flow_from_packet(char *packet[], int prefixes[], uint32_t *flow_key, MODE m) ;

extern inline int create_flow_from_packet_bin(packet_bin *packet, int prefixes[], uint32_t *flow_key, MODE m) ;

void (* MODE_CONVERSION_TABLE[11][11])(uint32_t *, uint32_t *)=
{{NULL, NULL, NULL, NULL, NULL, NULL, convert_2D_to_1D_first_element, convert_2D_to_1D_second_element, NULL, NULL, NULL},
 {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,convert_2D_to_1D_first_element , convert_2D_to_1D_second_element, NULL},
 {NULL, NULL, NULL, NULL, NULL, NULL, convert_2D_to_1D_first_element,NULL, convert_2D_to_1D_second_element, NULL, NULL},
 {NULL, NULL, NULL, NULL, NULL, NULL, convert_2D_to_1D_first_element, NULL, NULL, convert_2D_to_1D_second_element,NULL},
 {NULL, NULL, NULL, NULL, NULL, NULL, NULL, convert_2D_to_1D_first_element, convert_2D_to_1D_second_element, NULL, NULL},
 {NULL, NULL, NULL, NULL, NULL, NULL, NULL, convert_2D_to_1D_first_element, NULL, convert_2D_to_1D_second_element, NULL},
 {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},
 {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},
 {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},
 {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},
 {convert_FULL_SIDI, convert_FULL_SPDP, convert_FULL_SISP,convert_FULL_SIDP, convert_FULL_DISP, convert_FULL_DIDP, convert_FULL_SI, convert_FULL_DI, convert_FULL_SP, convert_FULL_DP, NULL},
};

void convert_2D_to_1D_first_element(uint32_t *dest_flow_key, uint32_t *src_flow_key){
  dest_flow_key[0] = src_flow_key[0];
  dest_flow_key[1] = src_flow_key[2];  
}
void convert_2D_to_1D_second_element(uint32_t *dest_flow_key, uint32_t *src_flow_key){
  dest_flow_key[0] = src_flow_key[1];
  dest_flow_key[1] = src_flow_key[3];  
}
void convert_FULL_SIDI(uint32_t *dest_flow_key, uint32_t *src_flow_key){
  dest_flow_key[0] = src_flow_key[0];
  dest_flow_key[1] = src_flow_key[1];
  dest_flow_key[2] = src_flow_key[4];
  dest_flow_key[3] = src_flow_key[5];
}
void convert_FULL_SPDP(uint32_t *dest_flow_key, uint32_t *src_flow_key){
  dest_flow_key[0] = src_flow_key[2];
  dest_flow_key[1] = src_flow_key[3];
  dest_flow_key[2] = src_flow_key[6];
  dest_flow_key[3] = src_flow_key[7];
}

void convert_FULL_SISP(uint32_t *dest_flow_key, uint32_t *src_flow_key){
  dest_flow_key[0] = src_flow_key[0];
  dest_flow_key[1] = src_flow_key[2];
  dest_flow_key[2] = src_flow_key[4];
  dest_flow_key[3] = src_flow_key[6];
}
void convert_FULL_SIDP(uint32_t *dest_flow_key, uint32_t *src_flow_key){
  dest_flow_key[0] = src_flow_key[0];
  dest_flow_key[1] = src_flow_key[3];
  dest_flow_key[2] = src_flow_key[4];
  dest_flow_key[3] = src_flow_key[7];
}

void convert_FULL_DISP(uint32_t *dest_flow_key, uint32_t *src_flow_key){
  dest_flow_key[0] = src_flow_key[1];
  dest_flow_key[1] = src_flow_key[2];
  dest_flow_key[2] = src_flow_key[5];
  dest_flow_key[3] = src_flow_key[6];
}


void convert_FULL_DIDP(uint32_t *dest_flow_key, uint32_t *src_flow_key){
  dest_flow_key[0] = src_flow_key[1];
  dest_flow_key[1] = src_flow_key[3];
  dest_flow_key[2] = src_flow_key[5];
  dest_flow_key[3] = src_flow_key[7];
}


void convert_FULL_SI(uint32_t *dest_flow_key, uint32_t *src_flow_key){
  dest_flow_key[0] = src_flow_key[0];
  dest_flow_key[1] = src_flow_key[4];
}
void convert_FULL_DI(uint32_t *dest_flow_key, uint32_t *src_flow_key){
  dest_flow_key[0] = src_flow_key[1];
  dest_flow_key[1] = src_flow_key[5];
}
void convert_FULL_SP(uint32_t *dest_flow_key, uint32_t *src_flow_key){
  dest_flow_key[0] = src_flow_key[2];
  dest_flow_key[1] = src_flow_key[6];
}
void convert_FULL_DP(uint32_t *dest_flow_key, uint32_t *src_flow_key){
  dest_flow_key[0] = src_flow_key[3];
  dest_flow_key[1] = src_flow_key[7];
}

int create_flow_from_tree_file(char **flow_str, uint32_t *flow_key, MODE m) {
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
        split(&buff2[buff2_index], &buff[j], "|");
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



void root_flow(uint32_t *parent_flow, MODE m) {
    int i = 0;
    for (i = 0; i < DIM; i++) {
        parent_flow[i] = 0;
        parent_flow[i + DIM] = 0;
    }
}


int parent_flow(uint32_t *node, uint32_t *parent_flow, MODE m) {
    int i;
    mask_idx idxs = MASK_IDXs[m];
    if (((int) node[DIM] <= 0)) {
        root_flow(parent_flow, m);
        return 1;
    }
    int inc1 = idxs.idx[0];
    if (((int) node[DIM] - (INCREM - inc1)) <= 0) {
        root_flow(parent_flow, m);
        return 1;
	}
    
    for (i = 0; i < DIM; i++) {
        int ip_or_port = idxs.idx[i];
        int inc = INCREM;
        const uint32_t *mask_list = MASK_TABLE[ip_or_port];
        inc -= ip_or_port;
        parent_flow[i + DIM] = node[i + DIM] - inc;
        parent_flow[i] = node[i] & mask_list[parent_flow[i + DIM]];
    }
    return 0;
}

void print_flow_key(uint32_t *flow_key, MODE m) {
  char * type;  
  char str[INET_ADDRSTRLEN];
  char str2[INET_ADDRSTRLEN];  
  if(m != SPDP && m!= SP && m!= DP){
    type = "src_ip";
    int_le_ip4_str(flow_key[0],str);  
  }else{
    type =  (m!=DP) ? "src_port" : "dst_port" ;
    int_le_to_str(flow_key[0], str); 
  }  
  fprintf(stderr, "print_flow_key: %s: %s/%u\t", type, str, (flow_key[DIM]));

  if((int)m > 5 && (int)m < 10) return;

  if(m!=SIDI && m!=FULL){
    type="dst_port";
    int_le_to_str(flow_key[1],str2); 
  }else{
    type="dst_ip";
    int_le_ip4_str(flow_key[1],str2);
  }  
  fprintf(stderr, "print_flow_key: %s: %s/%u\t",type, str2,flow_key[DIM +1]);

  if(m==FULL){
    fprintf(stderr," src_port: %u/%u, dst_port: %u/%u\t \n", flow_key[2], (flow_key[DIM +2]), flow_key[3], (flow_key[DIM + 3]));
  }

}
