noinst_LIBRARIES = libftree.a

libftree_a_SOURCES =   libflowtree/libflowtree/util.c libflowtree/libflowtree/util.h libflowtree/libflowtree/uthash.h libflowtree/libflowtree/utarray.h libflowtree/libflowtree/flow.c libflowtree/libflowtree/log.h libflowtree/libflowtree/log.c libflowtree/libflowtree/flow.h libflowtree/libflowtree/tree_node.c libflowtree/libflowtree/tree_node.h libflowtree/libflowtree/flow_tree_hmap.h libflowtree/libflowtree/flow_tree_hmap.c libflowtree/libflowtree/flow_tree.c libflowtree/libflowtree/flow_tree.h libflowtree/libflowtree/flow_tree_query.h libflowtree/libflowtree/flow_tree_query.c

AM_CFLAGS = -static -O3 -lpthread -ldl -lrt 
AM_CXXFLAGS =-std=c++0x -O3 -fopenmp
AM_CXXFLAGS +=-Ilibflowtree
AM_CXXFLAGS += -I.



DEFS = -DPACKAGE_NAME=\"Flowtree\" -DPACKAGE_TARNAME=\"flowtree\" -DPACKAGE_VERSION=\"4.0\" -DPACKAGE_STRING=\"Flowtree\ 4.0\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DPACKAGE=\"flowtree\"  -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1

bin_PROGRAMS =  flow_tree_create
flow_tree_create_SOURCES = flow_tree_create.cpp
flow_tree_create_LDADD=libftree.a




