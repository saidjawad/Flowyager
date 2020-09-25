#include <libflowtree/flow_tree.h>
#include <libflowtree/flow_tree_io.hpp>
#include <flow_agg/flow_agg_config.hpp>
#include <iostream>
#include <string>
#include <boost/algorithm/string.hpp>

int main(int argc,const char *argv[]){
  using namespace std;
  ft_config_t *ft = NULL;
  FlowAggConfig *conf = new FlowAggConfig(argv[1]);
  map<uint32_t, uint64_t> site_buffer_sizes;
  map<uint32_t , char *> site_buffers;
  int workload_status = 0 ;
  int failed = 0;
  if (conf->parse_result){
    cerr << "parsing the configuration file failed" << endl;
    return (conf->parse_result); 
  }
  cout << "input file name is " << conf->path_to_workload << endl;
  if (boost::algorithm::ends_with(conf->path_to_workload,".gz")) {
    std::string command = "zcat";
    command = command + " " + conf->path_to_workload;
    FILE *handle = popen(command.c_str(), "r");
    failed = str_pipe_to_buffers(conf->mac_to_site_map, site_buffers,
				 site_buffer_sizes,
				 conf->granularity, handle, &workload_status);    
    if (handle)
      pclose(handle);
    
  }else {
    FILE *handle = fopen((char *) conf->path_to_workload.c_str(), "r");
    failed = str_pipe_to_buffers(conf->mac_to_site_map, site_buffers,
				 site_buffer_sizes,
				 conf->granularity, handle, &workload_status);
    fclose(handle);
  }

  if(failed){
    cerr << "loading input file failed " << endl;
    return failed; 
  }
  uint32_t site_id  = conf->mac_to_site_map.begin()->second;
  ft = conf->config_blue_print;
  add_root(ft);
  char *buffer  = site_buffers[site_id];
  uint64_t buffer_size = site_buffer_sizes[site_id];
  packet_bin *packet = (packet_bin *) buffer;
  uint64_t buffer_index = 0;
  double buffer_start_time = *((double *) buffer);
  uint64_t passed_time = 0;
  size_t record_size = sizeof(packet_bin);
  ft->timestamp = (uint64_t) buffer_start_time;
  ft->mem_threshold = (uint64_t) (ft->memory_threshold * (double) ft->mem_max);
  cout << "building flowtree " << endl; 
  while(buffer_index < buffer_size){
    add_packet_bin(packet, ft);
    buffer_index += record_size;
    packet++;
    
  }

  string output_file_name = conf->output_path + "flow_tree.ascii" ;
  cout << "trying to save flowtree in " << output_file_name << endl;
  output_tree_file((char *)output_file_name.c_str(), &ft->TREE, ft->mode);
  
  return 0; 
}
