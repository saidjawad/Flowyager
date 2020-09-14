#ifndef FLOW_TREE_IO_H
#define FLOW_TREE_IO_H
#include <boost/foreach.hpp>
#include <iostream>
#include <string>
#include <sstream>
#include <map>
#include <cstddef>
#include <stdio.h>
#include <unistd.h>
#include <bits/stdc++.h>
#include <boost/algorithm/string.hpp>
#include <cmath>
using namespace std;
#ifdef __cplusplus
extern "C" {
  #endif
#include "flow_tree.h"
#include <pcap.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>

void read_tree_from_bin_file(char *tree_file, ft_config_t *conf);
void output_flow_tree_bin(char *output_file_name, ft_config_t *conf, flow_tree_meta * meta);
void read_tree_from_file(char *tree_file, tree_node **TREE, MODE m);
void output_tree_file(char *file_name, tree_node **TREE, MODE m);
void output_result_file(char *file_name, char *str, ft_config_t *conf);
int output_packet_bin(ft_config_t *config, map<string, uint32_t> &mac_to_site_map, map<uint32_t , char *>& site_buffers, map<uint32_t, uint64_t>& site_buffer_sizes);

int pcap_file_to_buffers(char *path_to_workload,  map<std::string , uint32_t>& mac_to_site, map<uint32_t , char *>& site_buffers, map<uint32_t, uint64_t>& site_buffer_sizes, uint32_t granularity);
void output_flow_tree_bin_optimized(char *output_file_name, ft_config_t *conf, flow_tree_meta * meta);
int parse_mac_to_site_map(char * macs,  map<string, uint32_t> &mac_to_site_map, int file_type);
int parse_converter_config(char *path, ft_config_t *config, map<string, uint32_t> &mac_to_site_map);
void init_site_stats_map(map<string, site_stats> & site_stats_map, map<std::string , uint32_t>& mac_to_site);
int output_packet_bin(ft_config_t *config, map<string, uint32_t> &mac_to_site_map, map<uint32_t , char *>& site_buffers, map<uint32_t, uint64_t>& site_buffer_sizes);
//  int str_file_to_buffers(ft_config_t *config,  map<string, uint32_t> &mac_to_site, map<uint32_t , char *>& site_buffers, map<uint32_t, uint64_t>& site_buffer_sizes, uint32_t granularity);

int str_pipe_to_buffers(map<string, uint32_t> &mac_to_site, map<uint32_t , char *>& site_buffers, map<uint32_t, uint64_t>& site_buffer_sizes, uint32_t granularity, FILE *handle, int *handle_done);
int read_packet_bin_file(char *file_name, char **buffer, uint64_t *buffer_size, ft_config_t *conf);
  void read_optimized_tree_from_bin_file(char *tree_file, ft_config_t *conf);
#ifdef __cplusplus
}
#endif
#endif
