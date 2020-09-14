
#ifndef UTIL_H
#define UTIL_H 1
#ifdef __cplusplus
extern "C" {
#endif
#define INCREM 2
#include<arpa/inet.h>
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include "log.h"
#include <pthread.h>
#define DBUG_LVL 5
#define DO_DEBUG(a,...) if((a)>=DBUG_LVL) log_trace(__VA_ARGS__)
#define DIM DIMS[m] 

#define int_le_ip4_str(a,b) int_be_ip4_str(htonl(a),(b))
#define str_to_le_int16(a) (uint16_t) atoi(a)
#define str_to_be_int16(a) (uint16_t) htons(atoi(a))
#define str_to_le_int32(a) (uint32_t) atoi(a)
#define str_to_be_int32(a)  (uint32_t) htonl(atoi(a))

typedef enum{SIDI,SPDP,
	     SISP,SIDP,
	     DISP,DIDP,
	     SI,DI,
	     SP,DP,
	     FULL}
  MODE;

typedef enum{
    BYTECOUNT,PACKETCOUNT,FLOWCOUNT
} COUNTMODE;

typedef enum{
    TCP,UDP,ALL
} PROTO;

typedef struct {
  int size;
  int idx[4];
}mask_idx;
  
typedef struct{
  uint32_t prefs[4];
  } max_prefs;

extern const mask_idx MASK_IDXs[11];
extern const uint32_t IP_MASKS[33];
extern const uint32_t PORT_MASKS[17];
extern const uint32_t *MASK_TABLE[2];
extern const uint32_t MODE_SIZES[11];  
extern const max_prefs MAX_PREFIXES[11];
extern const int DIMS[11];
extern  const mask_idx PACKET_IDXs[11];  
extern const MODE INT_TO_MODE[11];

  
inline uint32_t ip4_str_int_be(const char *str){
  struct in_addr val;
  int ret = inet_aton(str,&val);
  if(!ret){
    log_fatal("converting string ip address to uinteger failed %u \n",ret);
    exit(-1);
  }
  return  (uint32_t)val.s_addr;
}

inline void int_be_ip4_str(uint32_t ip_value,  char *str){
    inet_ntop(AF_INET, &(ip_value), str, INET_ADDRSTRLEN);
}
  
inline uint32_t ip4_str_int_le(const char *str){
  return ntohl(ip4_str_int_be(str));
}
  
inline int split(char **dst, char **src, char *str){
  int field = 0 ;
  char *value;
  while(( value = strsep(src,str))!=NULL){
    *(dst + field) = value;
    field++;
  }
  return field;
}    

inline void  int_le_to_str(uint32_t value,  char *str){
    snprintf(str,INET_ADDRSTRLEN, "%u", value);
  }

#ifdef __cplusplus
}
#endif
#endif
