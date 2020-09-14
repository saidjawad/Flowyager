#ifndef PACKET_BIN_H
#define PACKET_BIN_H
#ifdef __cplusplus
extern "C" {
  #endif
#include<stdint.h>
  #include <stdio.h>
  #include <unistd.h>
  #include <inttypes.h>
  #include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#define INPUT_TYPE_PCAP 0 
#define INPUT_TYPE_STR 1
#define INPUT_TYPE_PACKET_BIN 2 
#define USAGE_FAILURE -1
#define CONFIG_FAILURE -2
#define PKT_FAILURE -3
#define OUTPUT_BIN_FAILURE -4
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)
#define ETHER_ADDR_LEN 6
#define SRC_MAC_INDEX 7

struct struct_ethernet {
  u_char ether_dhost[ETHER_ADDR_LEN];/* destination host address */
  u_char ether_shost[ETHER_ADDR_LEN];/* source host address */
  u_short ether_type;/* IP? ARP? RARP? etc */
};

typedef struct packet_bin{
  double ts;
  uint32_t values[4];
  uint8_t proto;
  uint64_t packet_count[3];
} packet_bin;

typedef struct site_stats{
  char * site_buffer;
  uint64_t buffer_sizes;
  uint32_t buffer_size_pkt;
  uint32_t packets_read;
  uint32_t site_id;
} site_stats;

  typedef struct flow_tree_meta{
    uint8_t tree_mode;
    uint32_t tree_node_num;
    uint32_t granularity;
    uint64_t time_stamp;
    uint32_t site_id;
    int counter_type;
  }flow_tree_meta;


#ifdef __cplusplus
}
#endif
#endif
