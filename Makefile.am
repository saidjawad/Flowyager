noinst_LIBRARIES = libftree.a

libftree_a_SOURCES =  src/lib/sqlite3.c src/lib/sqlite3.h src/lib/util.c src/lib/util.h src/lib/uthash.h src/lib/utarray.h src/lib/flow.c src/lib/log.h src/lib/log.c src/lib/flow.h src/lib/tree_node.c src/lib/tree_node.h src/lib/flow_tree_hmap.h src/lib/flow_tree_hmap.c src/lib/flow_tree.c src/lib/flow_tree.h src/lib/flow_tree_query.h src/lib/flow_tree_query.c src/lib/fs_cache.h src/lib/fs_cache.c src/lib/fs_storage.h src/lib/fs_storage.c src/lib/fs_mongo_db.h src/lib/fs_mongo_db.c src/lib/packet_bin.h src/lib/flow_tree.h src/lib/flow_tree_io.cpp src/lib/ft_queue.h src/lib/ft_queue.c src/lib/fs_config.h src/lib/fs_config.c src/lib/fs_sync.cpp src/lib/fs_sync.h src/lib/query_engine.h src/lib/query_engine.cpp src/lib/fs_sync_server.cpp src/lib/fs_sync_server.h src/lib/sync_service_constants.cpp src/lib/sync_service_constants.h src/lib/sync_service_types.cpp src/lib/sync_service_types.h src/lib/fs_sync_client.h src/lib/fs_sync_client.cpp  src/lib/ttree_defs.h src/lib/ttree.h src/lib/ttree.c src/lib/FlowQLBaseVisitor.cpp src/lib/FlowQLVisitor.cpp src/lib/FlowQLParser.cpp src/lib/FlowQLLexer.cpp src/lib/SQLVisitor.h src/lib/SQLVisitor.cpp src/lib/r_query_engine.cpp src/lib/flow_agg_workload_manager.hpp src/lib/WorkloadMessageQueue.hpp src/lib/WorkloadMessageQueueImpl.hpp

AM_CFLAGS = -static $(MONGO_CFLAGS) $(CONFIG_CFLAGS) -O3 -lpthread -ldl -lrt 
#AM_CXXFLAGS = --static -pg -no-pie
AM_CXXFLAGS =-std=c++0x -O3 -fopenmp
AM_CXXFLAGS +=-static-libgcc
AM_CXXFLAGS +=-Isrc/lib
AM_CXXFLAGS +=-I/usr/local/include/antlr4-runtime
AM_CXXFLAGS += -I/usr/include/boolstuff-0.1
AM_CXXFLAGS += -I.
AM_CXXFLAGS += $(CONFIG_CFLAGS)
AM_CXXFLAGS += $(THRIFT_CFLAGS)
AM_CXXFLAGS += $(MONGO_CFLAGS)

DEFS = -DPACKAGE_NAME=\"Flowtree\" -DPACKAGE_TARNAME=\"flowtree\" -DPACKAGE_VERSION=\"4.0\" -DPACKAGE_STRING=\"Flowtree\ 4.0\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DPACKAGE=\"flowtree\"  -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1


#AM_LDFLAGS = -L/usr/local/lib
#AM_LDFLAGS = -static --force-link
#AM_LDFLAGS += -static
AM_LDFLAGS = -L/usr/lib/x86_64-linux-gnu -pthread  -fopenmp
AM_LDFLAGS += -L/usr/lib/gcc/x86_64-linux-gnu/6.3.0/
#AM_LDFLAGS += -lsqlite3
#AM_LDFLAGS += $(CONFIG_LIBS)
#AM_LDFLAGS += -l/usr/local/lib/libthrift.a
#AM_LDFLAGS += $(THRIFT_LIBS)
#AM_LDFLAGS += -lantlr4-runtime
#AM_LDFLAGS += -l/usr/local/lib/libantlr4-runtime.a
#AM_LDFLAGS += -Wl,-Bdynamic
#AM_LDFLAGS += $(MONGO_LIBS)
#AM_LDFLAGS += -L/usr/local/lib -lmongoc-static-1.0 -lssl -lcrypto -lrt -lresolv -pthread -lz -lbson-static-1.0 
#bin_PROGRAMS = fs_site flow_tree_exact flow_tree_diff flow_tree_merge fs_query
bin_PROGRAMS =  fs_site flow_tree_create_add_db r_query_engine fs_shell


fs_site_SOURCES = src/fs_site.cpp
fs_shell_SOURCES = src/fs_shell.cpp
flow_tree_create_add_db_SOURCES = src/flow_tree_create_add_db.cpp
#flow_tree_play_ground_SOURCES = src/flow_tree_play_ground.cpp
r_query_engine_SOURCES = src/lib/r_query_engine.cpp
#ft_create_SOURCES = src/ft_create.c
#flow_tree_exact_SOURCES = src/flow_tree_exact.cpp
#flow_tree_diff_SOURCES = src/flow_tree_diff.c
#flow_tree_merge_SOURCES =  src/flow_tree_merge.c
#fs_query_SOURCES =  src/fs_query.c


fs_site_LDADD = libftree.a /usr/lib/x86_64-linux-gnu/libssl.a /usr/lib/x86_64-linux-gnu/libcrypto.a /usr/lib/x86_64-linux-gnu/libconfig.a  /usr/local/lib/libthriftnb.a /usr/lib/x86_64-linux-gnu/libevent.a /usr/local/lib/libthrift.a /usr/local/lib/libantlr4-runtime.a /usr/local/lib/libcli.a /usr/lib/x86_64-linux-gnu/libboolstuff-0.1.a -L/usr/local/lib -lmongoc-static-1.0 /usr/lib/x86_64-linux-gnu/libssl.a /usr/lib/x86_64-linux-gnu/libcrypto.a -ldl -lcrypt -lgcc -lgcc_s -lrt -lresolv -lz -lbson-static-1.0 /usr/lib/x86_64-linux-gnu/librt.so /usr/lib/x86_64-linux-gnu/libm.so
#ft_create_LDADD = libftree.a /usr/lib/x86_64-linux-gnu/libconfig.a /usr/local/lib/libthrift.a /usr/local/lib/libantlr4-runtime.a -L/usr/local/lib -lmongoc-static-1.0 -lssl -lgcc -lgcc_s -lcrypto -lrt -lresolv -lz -lbson-static-1.0 /usr/lib/x86_64-linux-gnu/librt.so /usr/lib/x86_64-linux-gnu/libm.so
flow_tree_create_add_db_LDADD=libftree.a /usr/lib/x86_64-linux-gnu/libconfig.a  /usr/local/lib/libthriftnb.a /usr/lib/x86_64-linux-gnu/libevent.a /usr/local/lib/libthrift.a /usr/local/lib/libantlr4-runtime.a /usr/lib/x86_64-linux-gnu/libboolstuff-0.1.a -L/usr/local/lib -lmongoc-static-1.0 /usr/lib/x86_64-linux-gnu/libssl.a /usr/lib/x86_64-linux-gnu/libcrypto.a -ldl -lgcc -lgcc_s -lrt -lresolv -lz -lbson-static-1.0 /usr/lib/x86_64-linux-gnu/libpcap.a -lstdc++ /usr/lib/x86_64-linux-gnu/libboost_system.a /usr/lib/x86_64-linux-gnu/libboost_filesystem.a /usr/lib/x86_64-linux-gnu/libboost_thread.a /usr/lib/x86_64-linux-gnu/librt.so /usr/lib/x86_64-linux-gnu/libm.so 
#flow_tree_play_ground_LDADD=libftree.a /usr/lib/x86_64-linux-gnu/libconfig.a  /usr/local/lib/libthriftnb.a /usr/lib/x86_64-linux-gnu/libevent.a /usr/local/lib/libthrift.a /usr/local/lib/libantlr4-runtime.a /usr/lib/x86_64-linux-gnu/libboolstuff-0.1.a -L/usr/local/lib -lmongoc-static-1.0 /usr/lib/x86_64-linux-gnu/libssl.a /usr/lib/x86_64-linux-gnu/libcrypto.a -ldl -lgcc -lgcc_s -lrt -lresolv -lz -lbson-static-1.0 /usr/lib/x86_64-linux-gnu/libpcap.a -lstdc++ /usr/lib/x86_64-linux-gnu/libboost_system.a /usr/lib/x86_64-linux-gnu/libboost_filesystem.a /usr/lib/x86_64-linux-gnu/libboost_thread.a /usr/lib/x86_64-linux-gnu/librt.so /usr/lib/x86_64-linux-gnu/libm.so
r_query_engine_LDADD = libftree.a /usr/lib/x86_64-linux-gnu/libconfig.a  /usr/local/lib/libthriftnb.a /usr/lib/x86_64-linux-gnu/libevent.a /usr/local/lib/libthrift.a /usr/local/lib/libantlr4-runtime.a /usr/lib/x86_64-linux-gnu/libboolstuff-0.1.a -L/usr/local/lib -lmongoc-static-1.0 /usr/lib/x86_64-linux-gnu/libssl.a /usr/lib/x86_64-linux-gnu/libcrypto.a -ldl -lgcc -lgcc_s -lrt -lresolv -lz -lbson-static-1.0 /usr/lib/x86_64-linux-gnu/librt.so /usr/lib/x86_64-linux-gnu/libm.so
fs_shell_LDADD = libftree.a /usr/lib/x86_64-linux-gnu/libconfig.a  /usr/local/lib/libthriftnb.a /usr/lib/x86_64-linux-gnu/libevent.a /usr/local/lib/libthrift.a /usr/local/lib/libantlr4-runtime.a /usr/lib/x86_64-linux-gnu/libboolstuff-0.1.a -L/usr/local/lib -lmongoc-static-1.0 /usr/lib/x86_64-linux-gnu/libssl.a /usr/lib/x86_64-linux-gnu/libcrypto.a -ldl -lgcc -lgcc_s -lrt -lresolv -lz -lbson-static-1.0 /usr/lib/x86_64-linux-gnu/librt.so /usr/lib/x86_64-linux-gnu/libm.so
#flow_tree_exact_LDADD = libftree.a /usr/lib/x86_64-linux-gnu/libconfig.a -L/usr/local/lib /usr/lib/x86_64-linux-gnu/libpcap.a -lstdc++ /usr/lib/x86_64-linux-gnu/libboost_system.a /usr/lib/x86_64-linux-gnu/libboost_filesystem.a /usr/lib/x86_64-linux-gnu/libboost_thread.a /usr/lib/x86_64-linux-gnu/librt.so /usr/lib/x86_64-linux-gnu/libm.so
#flow_tree_diff_LDADD = libftree.a
#flow_tree_merge_LDADD = libftree.a
#fs_query_LDADD = libftree.a



