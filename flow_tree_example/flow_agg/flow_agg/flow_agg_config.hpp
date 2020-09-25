//
// Created by Said Jawad Saidi on 9/17/20.
//

#ifndef C_FLOW_AGG_CONFIG_H
#define C_FLOW_AGG_CONFIG_H
#include <string>
#include <map>
#include <stdint.h>
#include <libconfig.h>
#include <libflowtree/flow_tree.h>
#include <libflowtree/flow_tree_io.hpp>
#include <set>
#include <boost/algorithm/string.hpp>

class FlowAggConfig {
public:
    int parse_result ;
    int input_type;
    uint32_t granularity;
    uint32_t num_threads = 20;
    uint64_t dump_to_disk;
    int send_trees = 0;
    uint64_t send_only;
    std::string server_address = "localhost";
    std::string output_path = "";
    uint32_t server_port = 9090;
    std::string path_to_workload;
    std::string root_dir;
    int num_modes = 1;
    std::string mode_str;
    uint32_t task_queue_size = 2000;
    int modes[11];
    std::map<std::string, uint32_t> mac_to_site_map;
    uint64_t input_file_granularity = 1;
    ft_config_t *config_blue_print;
    std::string workload_queue_db_name = "test.db";
    int output_type = 0  ;

    FlowAggConfig(const char *path_to_config_file){
        this->config_blue_print = create_ft_config();

        this->parse_create_add_config(path_to_config_file);
    }
    FlowAggConfig(std::string &path_to_config_file){
        this->config_blue_print = create_ft_config();
        this->parse_create_add_config(path_to_config_file.c_str());
    }
private:
    int parse_modes() {
        using namespace std;
        vector<string> mode_strs;
        boost::split(mode_strs, mode_str, boost::is_any_of(","));
        set<int> mode_ints;
        for (auto mode: mode_strs) {
            mode_ints.insert(atoi(mode.c_str()));
        }
        int size = min(11, (int) mode_ints.size());
        num_modes = size;
        set<int>::iterator it;
        int i = 0;
        for (it = mode_ints.begin(); it != mode_ints.end(); ++it) {
            modes[i] = min(10, (int) *it);
            if (i >= size) break;
            i++;
        }

        return 0;
    }


    int parse_create_add_config(const char *path){
        parse_result = 0 ;
        config_t cfg;
        const char *str;
        long long value;
        double float_value;
	
        config_init(&cfg);
        if (!config_read_file(&cfg, path)) {
            fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
            config_destroy(&cfg);
            parse_result = 1;
            return (1);
        }

        
        if (config_lookup_int64(&cfg, "INPUT_TYPE", &value)) {
            input_type = (uint64_t) value;
            if (input_type < INPUT_TYPE_PACKET_BIN){
                config_lookup_string(&cfg, "MACS", &str);
                char *mac_to_site_str = strdup(str);
                if (parse_mac_to_site_map(mac_to_site_str, mac_to_site_map, input_type)) {
                    fprintf(stderr, "'MACS' setting in configuration file was in invalid format \n");
                    config_destroy(&cfg);
                    this->parse_result = 1;
                    return (1);
                }
             else {
	       fprintf(stderr, "parsing mac to site map failed \n");

            }

        } else {
            fprintf(stderr, "No 'INPUT_TYPE' setting in configuration file. Using default value - packet_bin\n");
        }
	     
	    
	if (config_lookup_string(&cfg, "PKT_FILE", &str)) {
            path_to_workload = string(str);
	    cout << "apth to workload " << path_to_workload << str << endl; 
        } else {

            fprintf(stderr, "No 'PKT_FILE' setting in configuration file, exiting...\n");
	    config_destroy(&cfg);
            parse_result = 1;
            return (1);
	    
        }
	    
        if (config_lookup_int64(&cfg, "GRANULARITY", &value)) {
            config_blue_print->granularity = (uint64_t) value;
	    this->granularity = (uint64_t) value;
        } else {
            config_blue_print->granularity = 15;
	    this->granularity = (uint64_t) value;
            fprintf(stderr, "No 'GRANULARITY' setting in configuration file. Using default value\n");
        }
        if (config_lookup_int64(&cfg, "NUM_THREADS", &value)) {
            num_threads = (int) value;
        } else {
            num_threads = 20;
            fprintf(stderr, "No 'NUM_THREADS' setting in configuration file. Using default value\n");
        }
        if (config_lookup_int64(&cfg, "DUMP_TO_DISK", &value)) {
            dump_to_disk = (uint64_t) value;
            if (dump_to_disk && config_lookup_int64(&cfg, "OUTPUT_TYPES", &value)) {
                output_type = (int) value;
            } else {
                output_type = 0;
                fprintf(stderr, "No 'OUTPUT_TYPES' setting in configuration file. Using default value\n");
            }
        } else {
            dump_to_disk = 0;
            fprintf(stderr, "No 'DUMP_TO_DISK' setting in configuration file. Using default value\n");
        }
        if (config_lookup_int64(&cfg, "SEND_TREES", &value)) {
            send_trees = value;
            if (config_lookup_int64(&cfg, "SEND_ONLY", &value)) {
                send_only = value;
            } else {
                send_only = 0;
            }
        } else {
            send_trees = 0;
            fprintf(stderr, "No 'SEND_TREES' setting in configuration file. Using default value of 0\n");
        }
        if (config_lookup_string(&cfg, "SERVER_IP", &str)) {
            server_address = string(str);

        } else {

            fprintf(stderr, "No 'SERVER_IP' setting in configuration file. Using default value\n");
        }
        


        if (config_lookup_string(&cfg, "MODES", &str)) {
            std::string mode_str(str);
            this->mode_str =mode_str;
            parse_modes();
        } else {	  
            num_modes = 1;
            modes[0] = 0;
            fprintf(stderr, "No 'MODES' setting in configuration file. Using default value\n");
        }
	this->config_blue_print->mode = INT_TO_MODE[modes[0]];

        if (config_lookup_string(&cfg, "OUT_PATH", &str)) {
            config_blue_print->out_path = strdup(str);
	    this->output_path = string(str);
        } else {
            config_blue_print->out_path = "out";
            fprintf(stderr, "No 'OUT_PATH' setting in configuration file. Using default value\n");
        }
        if (config_lookup_int64(&cfg, "PRINT", &value)) {
            config_blue_print->n_print = (uint64_t) value;
        } else {
            config_blue_print->n_print = 10000;
            fprintf(stderr, "No 'PRINT' setting in configuration file. Using default value\n");

        }
        if (config_lookup_int64(&cfg, "INPUT_FILE_GRANULARITY", &value)) {
            input_file_granularity = (uint64_t) value;
        } else {
            input_file_granularity = 0;
            fprintf(stderr, "No 'INPUT_FILE_GRANULARITY' setting in configuration file. Using default value of 1 minute\n");
        }

        if (config_lookup_int64(&cfg, "RECLAIM", &value)) {
            config_blue_print->n_reclaim = (uint64_t) value;
        } else {
            config_blue_print->n_reclaim = 40000;
            fprintf(stderr, "No 'RECLAIM' setting in configuration file. Using default value\n");
        }
        if (config_lookup_int64(&cfg, "MEMORY_MAX", &value)) {
            config_blue_print->mem_max = (uint64_t) value;
        } else {
            config_blue_print->mem_max = 40000;
            fprintf(stderr, "No 'MEMORY_MAX' setting in configuration file. Using default value\n");
        }
        if (config_lookup_float(&cfg, "TIME", &float_value)) {
            config_blue_print->time_int = (double) float_value;
        } else {
            config_blue_print->time_int = 1.0;
            fprintf(stderr, "No 'TIME' setting in configuration file. Using default value\n");
        }
        if (config_lookup_float(&cfg, "MEMORY_THRESHHOLD", &float_value)) {
            config_blue_print->memory_threshold = (double) float_value;
        } else {
            config_blue_print->memory_threshold = 0.6;
            fprintf(stderr, "No 'MEMORY_THRESHOLD' setting in configuration file. Using default value\n");
        }
        config_destroy(&cfg);
	
        return 0;
    }
}
};




#endif //C_FLOW_AGG_CONFIG_H
