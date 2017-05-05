/* 
* @Author: Xiaokang Yin
* @Date:   2017-05-05 19:30:49
* @Last Modified by:   Xiaokang Yin
* @Last Modified time: 2017-05-05 19:30:49
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "winsock2.h"

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;


typedef struct ether_header {
    u_char ether_dst[6];        //destination address
    u_char ether_src[6];        //source address
    u_short ehter_type;         //ethernet type
}ether_header;

//typedef struct ip_address {
//  u_char byte1;
//  u_char byte2;
//  u_char byte3;
//  u_char byte4;
//}ip_address;
//ipv4
typedef struct ip_header {
    u_char ver_ihl;     //version and length
    u_char tos;         //quality of the service
    u_short tlen;       //total length
    u_short identification;     //
    u_short offset;     //group offset
    u_char ttl;         // time to live
    u_char proto;       //protocol
    u_short checksum;   //
    u_char src[4];      //destination address
    u_char dst[4];      //source address
    //u_int op_pad;     //
}ip_header;
typedef struct psd_header {
    u_char src[4];
    u_char dst[4];
    u_char zero;
    u_char proto;
    u_short len;
}psd_header;
//tcp
typedef struct tcp_header {
    u_short dst_port;
    u_short src_port;
    u_int sequence;
    u_int ack;
    u_char hdrLen;              // 首部长度保留字
    u_char flags;
    u_short windows_size;
    u_short checksum;
    u_short urgent_pointer;
}tcp_header;

void hexdump(const u_char *pkt_content, u_int length);
u_short check_sum(u_short *buffer, int size);
u_short check_tcp_sum(u_char *buffer);
int replace_str(u_char *pkt_data, u_short pkt_len, u_char *str, int len, u_char *replace);