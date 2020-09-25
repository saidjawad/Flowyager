
lib_LTLIBRARIES =  libflowagg.la libftree.la

libflowagg_la_SOURCES = libflow_agg/libflow_agg/flow_agg_config.hpp

libflowagg_la_CPPFLAGS = -I$(top_srcdir)/../libflowtree

libftree_la_CXXFLAGS = -fPIC
libftree_la_CFLAGS = -fPIC

libftree_la_SOURCES =   libflowtree/libflowtree/util.c libflowtree/libflowtree/util.h libflowtree/libflowtree/uthash.h libflowtree/libflowtree/utarray.h libflowtree/libflowtree/flow.c libflowtree/libflowtree/log.h libflowtree/libflowtree/log.c libflowtree/libflowtree/flow.h libflowtree/libflowtree/tree_node.c libflowtree/libflowtree/tree_node.h libflowtree/libflowtree/flow_tree_hmap.h libflowtree/libflowtree/flow_tree_hmap.c libflowtree/libflowtree/flow_tree.c libflowtree/libflowtree/flow_tree.h libflowtree/libflowtree/flow_tree_query.h libflowtree/libflowtree/flow_tree_query.c libflowtree/libflowtree/flow_tree_io.hpp libflowtree/libflowtree/flow_tree_io.cpp



AM_CFLAGS =  -O3 -lpthread -ldl -lrt 
AM_CXXFLAGS =-std=c++0x -O3
AM_CXXFLAGS +=-Ilibflowtree
AM_CXXFLAGS += -I.
AM_CXXFLAGS+=-Iflow_agg
AM_CXXFLAGS += $(CONFIG_CFLAGS)

ACLOCAL_AMFLAGS = -I m4

AM_LDFLAGS = $(CONFIG_LIBS)
AM_LDFLAGS += -lpcap
DEFS = -DPACKAGE_NAME=\"Flowtree\" -DPACKAGE_TARNAME=\"flowtree\" -DPACKAGE_VERSION=\"4.0\" -DPACKAGE_STRING=\"Flowtree\ 4.0\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DPACKAGE=\"flowtree\"  -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1

bin_PROGRAMS =  flow_tree_create
flow_tree_create_SOURCES = flow_tree_create.cpp
libflowagg_la_LIBADD = libftree.la
flow_tree_create_LDADD=libflowagg.la libftree.la




