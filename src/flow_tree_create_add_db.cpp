#include <boost/foreach.hpp>
#include <iostream>
#include <boost/asio/io_service.hpp>
#include <boost/bind.hpp>
#include <boost/thread/thread.hpp>
#include <boost/filesystem.hpp>
#include <boost/range/iterator_range.hpp>
#include <condition_variable>
#include "fs_sync_client.h"
#include <string>
#include <thread>         // std::this_thread::sleep_for
#include <mutex>
#include <chrono>         // std::chrono::seconds
#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <cstddef>
#include "fs_cache.h"
#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctime>
#include <pthread.h>
#include <inttypes.h>
#include <bits/stdc++.h>
#include <boost/algorithm/string.hpp>
#include <math.h>
#include "flow_tree_io.h"
#include <malloc.h>
#include <sys/mman.h>
#include "WorkloadMessageQueue.hpp"
#include "WorkloadMessageQueueImpl.hpp"
#include "flow_agg_workload_manager.hpp"


#define OUTPUT_TYPE_ASCII 0
#define OUTPUT_TYPE_BIN 1
#define OUTPUT_TYPE_ASCII_BIN 2
#define INPUT_TREE_TYPE_BIN 0
#define INPUT_TREE_TYPE_ASCII 1
#define INPUT_TYPE_STR_IXP_PIPE 3

using namespace std;
std::mutex finished_mutex;
std::condition_variable cv;
std::mutex output_mutex;
namespace ft_util {
    std::mutex time_mutex;

    inline std::tm localtime(const std::time_t *timer) {
        std::lock_guard<std::mutex> lock(time_mutex);
        tm ret = *std::localtime(timer);
        return ret;
    }
}
typedef struct {
    map<uint32_t, char *> * site_buffers[2] ;
    map<uint32_t, uint64_t> * buffer_sizes[2];
    uint32_t granularity;
    map<std::string, uint32_t> mac_to_site;
    int last_workload;
    const char * path_to_workload;
    uint64_t workload_buffer_offset;
    FILE *workload_handle;
    int workload_handle_status;
} ft_workload_ctx;

typedef struct {
    ft_config_t *task_config;
    std::vector<ft_config_t *> *ftrees;
} ft_task;

typedef struct thread_init_info {
    int thread_id;
    ft_queue *job_queue;
    std::vector<ft_config_t *> *ftrees;
} thread_init_info;

typedef struct {
    std::vector<pthread_t *> threads;
    std::vector<ft_queue *> job_queues;
    pthread_attr_t *thread_attrs;
    std::vector<thread_init_info *> thread_inits;
} app_thread_info;
std::string server_address = "localhost";
int input_type = 0;
int output_type = 0;
int modes[11];
uint64_t mode_mem_max[11];
int mode_mem_max_defined = 0;
int num_modes = 1;
int send_only = 0;
int free_trees_after_send = 0;
uint32_t num_finished_jobs = 0;
int send_trees = 0;
uint64_t dump_to_disk = 0;
uint64_t input_file_granularity = 1;
int num_threads = 20;
std::string IPFIX_PARSER = "ipfixparser_10tuple_v4_tcp_udp_pkt_byte";
std::string root_dir;
std::string input_files_list_path;

void *create_and_send_ftrees(void *conf);

int create_tree_with_config(ft_config_t *config, uint64_t *buffer_idx, vector<ft_config_t *> *ftrees);

int set_attributes_from_file_name(std::string file_name, ft_config_t *config);

/* End of function Declarations */

int create_tree_with_config(ft_config_t *config, uint64_t *buffer_idx, vector<ft_config_t *> *ftrees) {
    uint64_t buffer_index = *buffer_idx;
    uint64_t buffer_size = config->n;
    if (!(buffer_index < buffer_size)) return 1;
    size_t record_size = sizeof(packet_bin);
    char *buffer = ((char *) config->gen_purpose_buffer) + buffer_index;
    double buffer_start_time = *((double *) buffer);
    double buffer_end_time = buffer_start_time;
    uint64_t passed_time = 0;

    for (auto a : *ftrees) {
        ft_config_t *ftree = (ft_config_t *) a;
        MODE m = ftree->mode;
        shallow_copy_tree(ftree, config);
        ftree->mode = m;
        add_root(ftree);
        ftree->timestamp = (uint64_t) buffer_start_time;
        ftree->mem_threshold = (uint64_t) (ftree->memory_threshold * (double) ftree->mem_max);
    }
    packet_bin *packet = (packet_bin *) (buffer);
    uint32_t num_pkts = 0;
    while (buffer_index < buffer_size && passed_time < (config->granularity * 60)) {
        num_pkts++;
        for (auto a : *ftrees) {
            ft_config_t *ftree = (ft_config_t *) a;
            add_packet_bin(packet, ftree);
        }
        buffer_end_time = packet->ts;
        passed_time = (uint64_t) (buffer_end_time - buffer_start_time);
        buffer_index += record_size;
        packet++;
    }
    if (num_pkts < 1) return 1;
    for (auto a : *ftrees) {
        ft_config_t *ftree = (ft_config_t *) a;
        ftree->n = num_pkts;
        uint64_t compression_target = (uint64_t) min((double) (0.05 * num_pkts), (double) (ftree->mem_max));
        compression_target = compression_target > 0 ? compression_target : 1;
        compression_target = ((ftree->mode == 8 || ftree->mode == 9) && compression_target >= 10000) ? 10000
                                                                                                     : compression_target;
        if ((uint64_t) compression_target < ftree->mem)
            compress_to_target(ftree, compression_target);
    }

    *buffer_idx = buffer_index;
    //  printf("passed_time is %lu , start_time %lf, end_time %lf, mode is %d , node_count %lu\n", passed_time,buffer_start_time,buffer_end_time, ftree->mode, HASH_COUNT(ftree->TREE));
    return 0;
}

int try_send_trees(ft_config_t *config, std::string file_name) {

    int num_retry = 0;
    int fail = 0;
    if (send_only) {
        switch (input_type) {
            case INPUT_TREE_TYPE_BIN:
                read_tree_from_bin_file((char *) file_name.c_str(), config);
                break;
            case INPUT_TREE_TYPE_ASCII:
                set_attributes_from_file_name(file_name, config);
                //fprintf(stderr, "%lu, %d\n",config->granularity, config->mode);
                read_tree_from_file((char *) file_name.c_str(), (tree_node **) &config->TREE, config->mode);
                break;
            default:
                if (config) free_ft_config(config);
                return -1;
        }
    }
    time_t start_t = std::time(0);
    while ((fail = send_flow_trees(config, 1, server_address.c_str(), 9090)) && num_retry < 10) {
        num_retry++;
        std::this_thread::sleep_for(std::chrono::seconds(num_retry));
    }
    if (send_only) {
        time_t end_t = std::time(0);
        uint32_t num_nodes = HASH_COUNT(config->TREE);
        long int start_int = static_cast<long int>(start_t);
        long int end_int = static_cast<long int>(end_t);
        output_mutex.lock();
        cout << file_name << "." << start_t << "." << end_t << "." << end_t - start_t << "." << num_retry << "." << fail
             << "." << num_nodes << endl;
        output_mutex.unlock();
        free_ft_config(config);
        malloc_trim(0);
        std::lock_guard<std::mutex> lck(finished_mutex);
        num_finished_jobs++;
        cv.notify_all();
    }
    return fail;
}

void flow_tree_to_meta(ft_config_t *ftree, flow_tree_meta *meta) {
    meta->tree_node_num = HASH_COUNT(ftree->TREE);
    meta->tree_mode = (uint8_t) ftree->mode;
    meta->granularity = ftree->granularity;
    meta->time_stamp = ftree->timestamp;
    meta->site_id = ftree->site_id;
}

int set_attributes_from_file_name(std::string file_name, ft_config_t *config) {
    vector<std::string> file_name_parts;
    boost::split(file_name_parts, file_name, boost::is_any_of("."));

    //fprintf(stderr,"%s, %s, %s, %s \n", (char *)file_name_parts[9].c_str(), (char* )file_name_parts[7].c_str(), (char *)file_name_parts[8].c_str(),(char* )file_name_parts[11].c_str());
    istringstream ts_stream(file_name_parts[8]);
    istringstream site_id_stream(file_name_parts[6]);
    istringstream granularity_stream(file_name_parts[7]);
    istringstream mode_stream(file_name_parts[10]);
    int mode;
    uint64_t timestamp;
    uint32_t granularity;
    uint32_t site_id;
    mode = std::stoi(file_name_parts[10], nullptr, 0);
    MODE m = INT_TO_MODE[mode];
    ts_stream >> timestamp;
    granularity_stream >> granularity;
    site_id_stream >> site_id;
    config->mode = m;
    config->timestamp = timestamp;
    config->granularity = granularity;
    config->site_id = site_id;
    return 0;
}

char *generate_file_name(ft_config_t *ftree) {
    char fname_buffer[200];
    char datetime_buffer[100];
    struct tm ts_local_time;
    time_t ts = ftree->timestamp;
    ts_local_time = ft_util::localtime(&ts);
    strftime(datetime_buffer, 100, "%Y-%m-%d-%H:%M:%S", &ts_local_time);
    //convert ts(time_t) to datetime
    sprintf(fname_buffer, "tree_file.%s.%lu.%lu.%lu.%uk.%u.tree", datetime_buffer, ftree->site_id, ftree->granularity,
            ftree->timestamp, ftree->mem_max / 1000, ftree->mode);
    char *result = (char *) calloc(strlen(fname_buffer) + 1, sizeof(char));
    strcpy(result, fname_buffer);
    return result;
}

void create_empty_trees(ft_config_t *config, vector<ft_config_t *> *ftrees) {
    for (int i = 0; i < num_modes; i++) {
        config->mode = INT_TO_MODE[modes[i]];
        ft_config_t *ftree = create_ft_config();
        ftrees->push_back(ftree);
        shallow_copy_tree(ftree, config);
        MODE m = ftree->mode;
        ftree->allocation_mode = BULK_AND_STACK;
        allocate_memory_tree(ftree);
    }

}

void reset_trees(vector<ft_config_t *> *ftrees) {
    for (ft_config_t *ftree : *ftrees) {
        //free_hmap_only(&ftree->TREE);
        HASH_CLEAR(hh, ftree->TREE);
        ftree->node_stack->head = -1;
        ftree->node_stack->empty = 1;
        ftree->node_stack->full = 0;
        free(ftree->TREE);
        tree_node *tree_nodes_buff = ftree->node_buffers;
        uint32_t *tree_keys_buff = ftree->flow_keys;
        MODE m = ftree->mode;
        for (uint32_t j = 0; j < ftree->mem_max; j++) {
            tree_node *node = &tree_nodes_buff[j];
            if (node->children != NULL) utarray_clear(node->children);
            if (node->children_bkp != NULL)utarray_clear(node->children_bkp);
            if (node->stats != NULL) reset_node_stats(node);
            node->flow_key = tree_keys_buff;
            //init_node(node);
            stack_push(ftree->node_stack, (void *) node);
            tree_keys_buff += 2 * DIM;
        }

    }
}

void destroy_trees(vector<ft_config_t *> *ftrees) {
    for (ft_config_t *ftree : *ftrees) {
        free_ft_config(ftree);

    }
}

void *create_and_send_ftrees(void *task) {
    ft_task *mytask = (ft_task *) task;
    vector<ft_config_t *> *ftrees = mytask->ftrees;
    ft_config_t *config = mytask->task_config;
    ft_config_t *ftree = NULL;
    uint32_t site_id = config->site_id;
    int mode = config->mode;
    string out_path(config->out_path);
    int num_trees = 0;
    uint64_t buffer_size = config->n;
    uint64_t buffer_idx = 0;
    uint64_t previous_buffer = 0;

    //create_empty_trees(config,ftrees);
    while (buffer_idx < buffer_size) {
        previous_buffer = buffer_idx;
        auto start = chrono::high_resolution_clock::now();
        int res = create_tree_with_config(config, &buffer_idx, ftrees);
        auto end = chrono::high_resolution_clock::now();
        if (!res) {
            for (auto a : *ftrees) {
                ft_config_t *ftree = (ft_config_t *) a;
                char *output_file_name = generate_file_name(ftree);
                string output_file_name_str(output_file_name);
                if (send_trees) try_send_trees(ftree, output_file_name_str);
                auto end2 = chrono::high_resolution_clock::now();
                //	    auto end2 = chrono::steady_clock::now();
                output_file_name_str = out_path + "/" + output_file_name_str;
                string output_file_name2_str(output_file_name);
                output_file_name2_str += ".ascii";
                output_file_name2_str = out_path + "/" + output_file_name2_str;
                if (dump_to_disk) {
                    flow_tree_meta meta;
                    flow_tree_to_meta(ftree, &meta);
                    switch (output_type) {
                        case OUTPUT_TYPE_ASCII:
                            output_tree_file((char *) output_file_name2_str.c_str(), &ftree->TREE, ftree->mode);
                        case OUTPUT_TYPE_BIN:
                            output_flow_tree_bin((char *) output_file_name_str.c_str(), ftree, &meta);
                            break;
                        case OUTPUT_TYPE_ASCII_BIN:
                            output_tree_file((char *) output_file_name2_str.c_str(), &ftree->TREE, ftree->mode);
                            output_flow_tree_bin((char *) output_file_name_str.c_str(), ftree, &meta);
                            break;
                        default:
                            fprintf(stderr, "Unknown output type, it should between 0 and 2\n");
                            break;
                    }
                }
                auto end_time_dump_to_disk = std::chrono::high_resolution_clock::now();
                //std::time(0);
                //long int end_time_dump_to_disk_int = static_cast<long int>(end_time_dump_to_disk);
                MODE m = ftree->mode;
                uint32_t f[DIM * 2];
                memset(f, 0, MODE_SIZES[m]);
                tree_node *node = get_flow_hmap_((const tree_node **) &ftree->TREE, (const uint32_t *) f, m);
                uint64_t total_count = 0;
                if (node) total_count = node->total_stat;

                output_mutex.lock();
                cout << output_file_name;
                cout << "." << chrono::duration_cast<chrono::milliseconds>(end - start).count();
                cout << "." << chrono::duration_cast<chrono::milliseconds>(end2 - start).count();
                cout << "." << start.time_since_epoch().count() << "." << end.time_since_epoch().count();
                cout << "." << end_time_dump_to_disk.time_since_epoch().count() << "." << dump_to_disk;
                cout << "." << output_type << "." << input_type << "." << previous_buffer << "." << buffer_idx;
                cout << "." << buffer_size << "." << HASH_COUNT(ftree->TREE) << "." << total_count << endl;
                output_mutex.unlock();
                num_trees++;
                free(output_file_name);
            }
            reset_trees(ftrees);
        } else {
            break;
        }
        //ftree = NULL;
    }

    free(config->gen_purpose_buffer);
    free(config->out_path);
    free_ft_config(config);
    //destroy_trees(ftrees);
    malloc_trim(0);
    std::lock_guard<std::mutex> lck(finished_mutex);
    num_finished_jobs++;
    cv.notify_all();

    //cout << "site_id " << site_id << " mode " << mode << " num_trees " << num_trees << endl;
    return 0;
}

int parse_modes(std::string mode_str) {
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

void print_buffer(char *buffer, uint64_t buffer_size) {
    uint64_t buffer_idx;
    size_t record_size = sizeof(packet_bin);
    packet_bin *packet = (packet_bin *) buffer;
    for (buffer_idx = 0; buffer_idx < buffer_size; buffer_idx += record_size) {
        printf("%lf  ", packet->ts);

        char str_ip4_src[INET_ADDRSTRLEN];
        char str_ip4_dst[INET_ADDRSTRLEN];
        uint32_t src = htonl(packet->values[0]);
        uint32_t dst = htonl(packet->values[1]);
        inet_ntop(AF_INET, &(src), str_ip4_src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(dst), str_ip4_dst, INET_ADDRSTRLEN);

        printf("%s %s ", str_ip4_src, str_ip4_dst);
        printf("%lu %lu %d %lu\n", packet->values[2], packet->values[3], packet->proto, packet->packet_count[0]);
        packet++;
    }
}

ft_config_t *create_tree_config(ft_config_t *conf, char *buffer, uint64_t buffer_size, int mode, uint32_t site_id) {
    ft_config_t *config = create_ft_config();
    MODE m = conf->mode;
    conf->mode = INT_TO_MODE[mode];
    shallow_copy_tree(config, conf);
    config->out_path = strdup(conf->out_path);
    config->gen_purpose_buffer = (void *) buffer;
    config->n = buffer_size;
    config->site_id = site_id;
    config->mode = INT_TO_MODE[mode];
    return config;
}

void *worker_thread(void *arg) {
    //mini_job *job = (mini_job *)arg;
    thread_init_info *info = (thread_init_info *) arg;
    uint32_t thread_id = info->thread_id;
    ft_queue *job_queue = (ft_queue *) info->job_queue;
    std::vector<ft_config_t *> *ftrees = new std::vector<ft_config_t *>;
    for (;;) {
        pthread_mutex_lock(job_queue->mut);
        if (job_queue->empty) {
            pthread_cond_wait(job_queue->not_empty, job_queue->mut);
        }
        if (job_queue->empty) {
            break;
        }
        void *config = NULL;
        queue_pop(job_queue, &config);
        pthread_mutex_unlock(job_queue->mut);
        ft_config_t *my_conf = (ft_config_t *) config;
        ft_task task;
        my_conf->n_print = thread_id;
        if (ftrees->size() == 0) {
            create_empty_trees(my_conf, ftrees);
        }
        task.task_config = my_conf;
        task.ftrees = ftrees;
        create_and_send_ftrees(&task);
    }
    destroy_trees(ftrees);
    delete ftrees;

}

void init_threads(app_thread_info *app) {
    std::vector<pthread_t *> &threads = ref(app->threads);
    std::vector<ft_queue *> &job_queues = ref(app->job_queues);

    int numberOfProcessors = sysconf(_SC_NPROCESSORS_ONLN);
    num_threads = num_threads <= numberOfProcessors ? num_threads : numberOfProcessors;

    pthread_attr_t *attr = (pthread_attr_t *) calloc(1, sizeof(pthread_attr_t));
    cpu_set_t *cpus = (cpu_set_t *) calloc(1, sizeof(cpu_set_t));
    pthread_attr_init(attr);
    app->thread_attrs = attr;

    long DEFAULT_WORKER_TASK_QUEUE_SIZE = 100;

    for (uint16_t thread_num = 0; thread_num < num_threads; thread_num++) {

        pthread_t *thread = (pthread_t *) calloc(1, sizeof(pthread_t));
        threads.push_back(thread);

        ft_queue *job_queue = queue_new(DEFAULT_WORKER_TASK_QUEUE_SIZE);
        job_queues.push_back(job_queue);

        thread_init_info *info = (thread_init_info *) calloc(1, sizeof(thread_init_info));
        info->thread_id = thread_num;
        info->job_queue = job_queue;
        app->thread_inits.push_back(info);
        CPU_ZERO(cpus);
        CPU_SET(thread_num, cpus);

        pthread_attr_setaffinity_np(attr, sizeof(cpu_set_t), cpus);
        pthread_create(thread, attr, &worker_thread, (void *) info);

    }

}


int find_and_get_workload(std::string &path_to_workload, WorkloadMessageQueue *workload_queue) {
    workload_desc * descr = NULL;
    int rc = -1;
    cout << " checking for workload \n" << endl;
    if (!workload_queue->isWorkloadQueueEmpty()){
        rc = workload_queue->popWorkload((void **)&descr);
        if(!rc){
         path_to_workload = descr->workload_name;
         cout << "found the workload in find_and_get_workload " << path_to_workload << endl;
         if(descr != NULL){
             free(descr);
         }
        }

    }
    return rc;
}

int load_IXP_input_files_from_pipe(ft_config_t *config, map<string, uint32_t> &mac_to_site,
                                   map<uint32_t, char *> &site_buffers, map<uint32_t, uint64_t> &site_buffer_sizes,
                                   uint32_t granularity) {
    string pkt_file = string(config->pkt_file);
    using namespace boost::algorithm;
    string command;
    if (ends_with(pkt_file, ".gz")) command = "zcat";
    else if (ends_with(pkt_file, ".pcap")) command = "cat";
    else return 1;
    command = command + " " + pkt_file + " | " + IPFIX_PARSER + " - ";
    FILE *pipe_handle = popen(command.c_str(), "r");
    if (!pipe_handle)
        return 1;
    int ret = str_pipe_to_buffers(mac_to_site,
                                  site_buffers, site_buffer_sizes,
                                  granularity, pipe_handle, NULL);
    pclose(pipe_handle);
    return ret;

}
int is_workload_finished(ft_workload_ctx * ctx){
    cout << "workload status is " << ctx->workload_handle_status << endl;
    return ctx->workload_handle_status;

}
int load_workload_input(ft_workload_ctx * ctx) {
    char *buffer = NULL;
    uint64_t buffer_size = 0;
    if (!send_only) {
        int failed = 0;
        switch (input_type) {
            case INPUT_TYPE_PACKET_BIN:
//                failed = read_packet_bin_file(input_file_char, &buffer, &buffer_size, app_config);
//                if (!failed) {
//                    site_buffers[app_config->site_id] = buffer;
//                    site_buffer_sizes[app_config->site_id] = buffer_size;
//                } else {
//                    printf("input_type : %d\n", input_type);
//                }
                break;
            case INPUT_TYPE_PCAP:
                ctx->last_workload ^= 1 ;
                ctx->workload_handle_status = 1;
//                failed = pcap_file_to_buffers(ctx->path_to_workload, ctx->mac_to_site,
//                                              ctx->site_buffers[ctx->last_workload],
//                                              ctx->buffer_sizes[ctx->last_workload],
//                                              ctx->granularity);
                break;
            case INPUT_TYPE_STR:
            {
                cout << "loading workload input" << ctx->path_to_workload << endl;
                ctx->last_workload ^= 1;
                if(ctx->workload_handle_status) {
                    FILE *handle = fopen((char *) ctx->path_to_workload, "r");
                    ctx->workload_handle = handle;
                }
                if(ctx->workload_handle != NULL) {
                    cout << "passed the workload for loading" << endl;
                    failed = str_pipe_to_buffers(ctx->mac_to_site, *(ctx->site_buffers[ctx->last_workload]),
                                                  *(ctx->buffer_sizes[ctx->last_workload]),
                                                 ctx->granularity, ctx->workload_handle, &ctx->workload_handle_status);
                    if(ctx->workload_handle_status == 1 || failed){
                        if(ctx->workload_handle != NULL){
                            fclose(ctx->workload_handle);
                        }
                        ctx->workload_handle = NULL;
                    }
                }
            }
                break;
            case INPUT_TYPE_STR_IXP_PIPE:
//                failed = load_IXP_input_files_from_pipe(app_config, mac_to_site, site_buffers, site_buffer_sizes,
//                                                        input_file_granularity);
                break;
            default:
                failed = 1;
                break;
        }
        return failed;
    }
}

uint32_t create_tasks(ft_config_t *conf, ft_queue *task_queue, ft_workload_ctx * ctx) {
    std::pair<uint32_t, char *> p;
    uint32_t num_jobs = 0;
    std::map<uint32_t, char*> site_buffers = *(ctx->site_buffers[ctx->last_workload]);
    BOOST_FOREACH(p, site_buffers) {
                    ft_config_t *config;
                    void *config_voided;
                    uint64_t buffer_size = ctx->buffer_sizes[ctx->last_workload]->find(p.first)->second;
                    config = create_tree_config(conf, p.second, buffer_size, modes[0], p.first);
                    config_voided = (void *) config;
                    queue_push(task_queue, config_voided);
                    num_jobs++;
                }
    cout << "Num jobs is " << num_jobs << endl;
    return num_jobs;
}

void schedule_tasks(ft_queue *task_queue, std::vector<ft_queue *> &job_queues) {
    int tasks_finished = 0;
    int i = 0;
    while (!tasks_finished) {
        for (int i = 0; i < num_threads; i++) {
            if (task_queue->empty) {
                tasks_finished = 1;
                break;
            }
            ft_queue *job_queue = job_queues[i];
            pthread_mutex_lock(job_queue->mut);
            if (!job_queue->full) {
                void *task = NULL;
                queue_pop(task_queue, &task);
                queue_push(job_queue, task);
            }
            pthread_mutex_unlock(job_queue->mut);
            pthread_cond_signal(job_queue->not_empty);
        }
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    cout << "scheduled all the jobs " << endl;

}


void flow_agg_run(ft_config_t *conf, map<std::string, uint32_t> &mac_to_site, WorkloadMessageQueue *workload_queue) {
    map<uint32_t, char *> site_buffers[2];
    map<uint32_t, uint64_t> buffer_sizes[2];
    ft_workload_ctx workload_ctx ;
    workload_ctx.site_buffers[0] = &site_buffers[0];
    workload_ctx.site_buffers[1] = &site_buffers[1];
    workload_ctx.buffer_sizes[0] = &buffer_sizes[0];
    workload_ctx.buffer_sizes[1] = &buffer_sizes[1];
    workload_ctx.mac_to_site = mac_to_site;
    workload_ctx.workload_handle_status = 1;
    workload_ctx.workload_handle = NULL;
    app_thread_info app;
    uint32_t num_jobs = 0;
    std::pair<uint32_t, char *> p;
    int k = 0;
    std::vector<pthread_t *> threads;//[num_threads];
    uint64_t tmp_mem_max = conf->mem_max;
    ft_queue *task_queue = queue_new(2000);
    init_threads(&app);
    while (true) {
        std::string path_to_workload;
        if (!find_and_get_workload(path_to_workload, workload_queue)) {
            cout << "found workload in flow_agg_run" << path_to_workload << endl;
            workload_ctx.path_to_workload = path_to_workload.c_str();
            workload_ctx.granularity = conf->granularity;

            do{
                if(!load_workload_input(&workload_ctx)){
                    num_jobs = create_tasks(conf, task_queue, &workload_ctx);
                    cout << "scheduling tasks " << endl;
                    schedule_tasks(task_queue, app.job_queues);
                    workload_ctx.site_buffers[workload_ctx.last_workload]->clear();
                    workload_ctx.buffer_sizes[workload_ctx.last_workload]->clear();
                };
            }while(!is_workload_finished(&workload_ctx));
        }
        //exit(0);
        
    }

    //start_timepoint = found_timepoint;
/*  uint32_t remaining_tasks = num_jobs;
 int i = 0;
 std::unique_lock <std::mutex> lck(finished_mutex);
 while (num_finished_jobs < num_jobs) {
   cv.wait(lck);
 }
 
 for (i = 0; i < num_threads; i++) {
   ft_queue *job_queue = app.job_queues[i];
   pthread_cond_signal(job_queue->not_empty);
 }
 
 for (i = 0; i < num_threads; i++) {
   pthread_t *thread = app.threads[i];
   pthread_join(*thread, NULL);
   ft_queue *job_queue = app.job_queues[i];
   queue_destroy(job_queue);
   thread_init_info *info = app.thread_inits[i];
   free(info);
   }*/
    queue_destroy(task_queue);

}

void parallel_send_ftrees_only(ft_config_t *config) {
    using namespace boost::filesystem;
    boost::asio::io_service ioService;
    boost::thread_group threadpool;
    boost::asio::io_service::work work(ioService);
    free_trees_after_send = 1;
    std::size_t(boost::asio::io_service::*
    run)() = &boost::asio::io_service::run;
    for (int thread_num = 0; thread_num < num_threads; thread_num++) {
        threadpool.create_thread(boost::bind(run, &ioService));
    }
    path p(config->out_path);
    int i = 0;
    vector<std::string> file_names;
    string extension = ".tree";
    switch (input_type) {
        case INPUT_TREE_TYPE_BIN:
            extension = ".tree";
            break;
        case INPUT_TREE_TYPE_ASCII:
            extension = ".ascii";
            break;
        default:
            fprintf(stderr, "Unknown input type\n");
            exit(EXIT_FAILURE);
    }
    //select subset of files with the specified extension
    for (auto &entry: boost::make_iterator_range(directory_iterator(p), {})) {
        if (entry.path().extension() == extension) {
            //fprintf(stderr, "%s\n",entry.path().native());
            file_names.push_back(std::string(entry.path().native()));
        }
    }
    std::sort(file_names.begin(), file_names.end());
    //find total number of threads to be sent;
    uint32_t num_jobs = file_names.size();
    //fprintf(stderr, "num jobs is %lu\n", num_jobs);
    for (auto fname: file_names) {
        //fprintf(stderr, "%s\n",(char *)fname.c_str());
        ft_config_t *config = create_ft_config();
        if (config) ioService.post(boost::bind(try_send_trees, config, fname));
    }
    std::unique_lock<std::mutex> lck(finished_mutex);
    while (num_finished_jobs < num_jobs) cv.wait(lck);
    ioService.stop();
    threadpool.join_all();
}

int parse_create_add_config(char *path, ft_config_t *config, map<string, uint32_t> &mac_to_site_map) {
    config_t cfg;
    const char *str;
    long long value;
    double float_value;

    config_init(&cfg);
    if (!config_read_file(&cfg, path)) {
        fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return (EXIT_FAILURE);
    }

    if (config_lookup_int64(&cfg, "INPUT_TYPE", &value)) {
        input_type = (uint64_t) value;
        if ((input_type < INPUT_TYPE_PACKET_BIN || input_type == INPUT_TYPE_STR_IXP_PIPE) &&
            config_lookup_string(&cfg, "MACS", &str)) {
            char *mac_to_site_str = strdup(str);
            if (parse_mac_to_site_map(mac_to_site_str, mac_to_site_map, input_type)) {
                fprintf(stderr, "'MACS' setting in configuration file was in invalid format \n");
                config_destroy(&cfg);
                return (EXIT_FAILURE);
            }
        } else {
            /*printf("input type %lu\n", input_type);
            fprintf(stderr, "No 'MACS' setting in configuration file. exiting\n");
            config_destroy(&cfg);
            return (EXIT_FAILURE);*/
        }

    } else {
        fprintf(stderr, "No 'INPUT_TYPE' setting in configuration file. Using default value - packet_bin\n");
    }

    if (config_lookup_int64(&cfg, "GRANULARITY", &value)) {
        config->granularity = (uint64_t) value;
    } else {
        config->granularity = 15;
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

    if (config_lookup_string(&cfg, "INPUT_FILE_LIST", &str)) {
        input_files_list_path = string(str);

    } else {

        fprintf(stderr, "No 'INPUT_FILE_LIST' setting in configuration file. Using default value\n");
    }

    if (config_lookup_string(&cfg, "ROOT_DIR_WATCH", &str)) {
        root_dir = string(str);

    } else {

        fprintf(stderr, "No 'ROOT_DIR_WATCH' setting in configuration file. Using default value\n");
    }

    if (config_lookup_string(&cfg, "MODES", &str)) {
        string mode_str(str);
        parse_modes(mode_str);
    } else {
        num_modes = 1;
        modes[0] = 0;
        fprintf(stderr, "No 'MODES' setting in configuration file. Using default value\n");
    }

    if (config_lookup_string(&cfg, "DATA_PATH", &str)) {
        config->data_path = strdup(str);
    } else {
        config->data_path = "data";
        fprintf(stderr, "No 'DATA_PATH' setting in configuration file. Using default value\n");
    }
    //log_trace("data_path directory is %s\n", conf->data_path);

    if (config_lookup_string(&cfg, "OUT_PATH", &str)) {
        config->out_path = strdup(str);
    } else {
        config->out_path = "out";
        fprintf(stderr, "No 'OUT_PATH' setting in configuration file. Using default value\n");
    }
    //log_trace("out_path directory is %s\n", conf->out_path);

    /*    if (config_lookup_string(&cfg, "PKT_FILE", &str)) {
        config->pkt_file = strdup(str);
    } else {
        fprintf(stderr, "No 'PKT_FILE' setting in configuration file. Exiting...\n");
        config_destroy(&cfg);
        return (EXIT_FAILURE);
	}*/
    if (config_lookup_int64(&cfg, "PRINT", &value)) {
        config->n_print = (uint64_t) value;
    } else {
        config->n_print = 10000;
        fprintf(stderr, "No 'PRINT' setting in configuration file. Using default value\n");

    }
    //log_trace("PRINT value is %lu\n", conf->n_print);
    if (config_lookup_int64(&cfg, "INPUT_FILE_GRANULARITY", &value)) {
        input_file_granularity = (uint64_t) value;
    } else {
        input_file_granularity = 0;
        fprintf(stderr, "No 'INPUT_FILE_GRANULARITY' setting in configuration file. Using default value of 1 minute\n");
    }

    if (config_lookup_int64(&cfg, "RECLAIM", &value)) {
        config->n_reclaim = (uint64_t) value;
    } else {
        config->n_reclaim = 40000;
        fprintf(stderr, "No 'RECLAIM' setting in configuration file. Using default value\n");
    }
    if (config_lookup_int64(&cfg, "MEMORY_MAX", &value)) {
        config->mem_max = (uint64_t) value;
    } else {
        config->mem_max = 40000;
        fprintf(stderr, "No 'MEMORY_MAX' setting in configuration file. Using default value\n");
    }
    //log_trace("MEMORY_MAX value is %lu\n", conf->mem_max);

    if (config_lookup_float(&cfg, "TIME", &float_value)) {
        config->time_int = (double) float_value;
    } else {
        config->time_int = 1.0;
        fprintf(stderr, "No 'TIME' setting in configuration file. Using default value\n");
    }
    if (config_lookup_float(&cfg, "MEMORY_THRESHHOLD", &float_value)) {
        config->memory_threshold = (double) float_value;
    } else {
        config->memory_threshold = 0.6;
        fprintf(stderr, "No 'MEMORY_THRESHOLD' setting in configuration file. Using default value\n");
    }

    //log_trace("PKT_FILE is %s\n", conf->pkt_file);
    config_destroy(&cfg);
    return 0;
}


int main(int argc, char *argv[]) {
    char *buffer = NULL;
    uint64_t buffer_size = 0;
    map<std::string, uint32_t> mac_to_site;
    ft_config_t *config = create_ft_config();
    int parse_ret = parse_create_add_config(argv[1], config, mac_to_site);
    if (!parse_ret) {
        cout << "instantiating message queue" << endl;
        WorkloadMessageQueue *workload_queue = new WorkloadMessageQueueImpl("test.db");
        cout << "instantiating workload manager " << endl;
        FlowAGGWorkloadManager *workload_manager = new FlowAGGWorkloadManager(workload_queue,
                root_dir, input_files_list_path);
        std::thread th(&FlowAGGWorkloadManager::run_workload_manager, workload_manager);
        flow_agg_run(config, mac_to_site, workload_queue);
        th.join();
        /*    if (!send_only) {
               int failed = 0;
               string input_file = string(config->data_path) + "/" + string(config->pkt_file);
               char *input_file_char = (char *) input_file.c_str();
               switch (input_type) {
                   case INPUT_TYPE_PACKET_BIN:
                       failed = read_packet_bin_file(input_file_char, &buffer, &buffer_size, config);
                       if (!failed) {
                           site_buffers[config->site_id] = buffer;
                           site_buffer_sizes[config->site_id] = buffer_size;
                       } else {
                           printf("input_type : %d\n", input_type);
                       }
                       break;
                   case INPUT_TYPE_PCAP:
                       failed = pcap_file_to_buffers(config, mac_to_site, site_buffers, site_buffer_sizes,
                                                     input_file_granularity);
                       break;
                   case INPUT_TYPE_STR:
                       failed = str_file_to_buffers(config, mac_to_site, site_buffers, site_buffer_sizes,
                                                    input_file_granularity);
                       break;
                   default:
                       failed = 1;
                       break;
               }*/
        // if (!failed) {
        //      parallel_create2(config, site_buffers, site_buffer_sizes);
        //flow_agg_run(config, mac_to_site);
        //parallel_create_and_send_ftrees(config, site_buffers, site_buffer_sizes);
        // } else {
        //fprintf(stderr, "Reading input file into buffers failed %d\n", failed);
        // return failed;
        // }
        //        } else {
        //parallel_send_ftrees_only(config);
        // }
    } else {
        cout << 'parsing configuration file failed' << endl;
        return parse_ret;
    }
}
