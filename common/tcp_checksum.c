/* 
* @Author: Xiaokang Yin
* @Date:   2017-05-05 19:28:25
* @Last Modified by:   Xiaokang Yin
* @Last Modified time: 2017-05-05 19:33:31
*/
#include "ip_checksum.h"


void hexdump(const u_char *pkt_content, u_int length)
{
    const u_char *data = (u_char *)pkt_content;
    //u_char length = strlen(data);
    u_char text[17] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    u_int i = 0;
    u_char j;
    for (i = 0; i < length; i++) {
        if (i % 16 == 0) printf("%08d  ", i / 16);
        printf("%02X ", data[i]);
        text[i % 16] = (data[i] >= 0x20 && data[i] <= 0x7E) ? data[i] : '.';
        if ((i + 1) % 8 == 0 || i + 1 == length) printf(" ");
        if (i + 1 == length && (i + 1) % 16 != 0) {
            text[(i + 1) % 16] = '\0';
            for (j = (i + 1) % 16; j < 16; j++) printf("   ");
            if ((i + 1) % 16 <= 8) printf(" ");
        }
        if ((i + 1) % 16 == 0 || i + 1 == length) printf("|%s|\n", text);
    }

}

u_short check_sum(u_short *buffer, int size)
{
    unsigned long cksum = 0;
    while (size>1)
    {
        cksum += *buffer++;
        size -= 2;
    }
    if (size)
    {
        cksum += *(u_char *)buffer;
    }
    //将32位数转换成16
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return ~cksum;
}

u_short check_tcp_sum(u_char *buffer)  //传递报文开始
{
    u_char *tcp_sum_block;//psd header + tcp header + data
    psd_header *psd_head;
    ip_header *ip_protocol;
    tcp_header *tcp_protocol;
    u_char ip_header_len;
    u_char tcp_header_len;
    u_short old_checksum;
    u_short new_checksum;
    ip_protocol = (ip_header *)(buffer + 14);
    ip_header_len = (ip_protocol->ver_ihl & 0xf) * 4;
    printf("ip_header_len is %d\n", ip_header_len);
    tcp_protocol = (tcp_header *)(buffer + 14 + 20);
    tcp_header_len = (tcp_protocol->hdrLen >> 4) * 4;
    printf("tcp_header_len is %d\n", tcp_header_len);
    u_short len = ntohs(ip_protocol->tlen);
    //printf("len %x\n", len);

    u_short new_len = len + sizeof(struct psd_header);
    //printf("new len %x\n", new_len);
    tcp_sum_block = (u_char *)malloc(new_len);
    if (tcp_sum_block == NULL)
    {
        printf("malloc wrong!");
        return -1;
    }
    memset(tcp_sum_block, NULL, new_len);
    psd_head = (psd_header *)tcp_sum_block;
    //printf("ip protocol src %x\n", ip_protocol->src[0]);
    //printf("ip protocol dst %x\n", ip_protocol->dst[0]);
    psd_head->src[0] = ip_protocol->src[0];
    psd_head->src[1] = ip_protocol->src[1];
    psd_head->src[2] = ip_protocol->src[2];
    psd_head->src[3] = ip_protocol->src[3];
    psd_head->dst[0] = ip_protocol->dst[0];
    psd_head->dst[1] = ip_protocol->dst[1];
    psd_head->dst[2] = ip_protocol->dst[2];
    psd_head->dst[3] = ip_protocol->dst[3];
    
    psd_head->zero = 0;
    psd_head->proto = 0x06;
    psd_head->len = htons(len - ip_header_len); ///
    old_checksum = tcp_protocol->checksum;
    printf("old check sum %x\n", old_checksum = tcp_protocol->checksum);
    tcp_protocol->checksum = 0;
    
    //printf("src_ip %x\n", psd_head->src);
    //printf("dst_ip %x\n", psd_head->dst[0]);
    //printf("psd_head len 0x%x\n", ntohs(psd_head->len));
    //hexdump(psd_head, sizeof(psd_header));
    memcpy(tcp_sum_block + sizeof(psd_header), tcp_protocol, len - ip_header_len);
    //hexdump(tcp_sum_block, new_len - 20);
    tcp_protocol->checksum = check_sum(tcp_sum_block, new_len - ip_header_len);
    new_checksum = tcp_protocol->checksum;
    printf("new check sum %x\n", new_checksum = tcp_protocol->checksum);
    if (old_checksum != new_checksum)
    {
        printf("old check sum %x\n", old_checksum);
        printf("new check sum %x\n", new_checksum);
        printf("src ip %d.%d.%d.%d\n", psd_head->src[0], psd_head->src[1], psd_head->src[2], psd_head->src[3]);
        printf("dst ip %d.%d.%d.%d\n", psd_head->dst[0], psd_head->dst[1], psd_head->dst[2], psd_head->dst[3]);
    }
    free(tcp_sum_block);
    tcp_sum_block = NULL;

}

int replace_str(u_char *pkt_data, u_short pkt_len, u_char *str,int str_len, u_char *replace)
{
    u_char *fp = NULL;
    int i, j;
    int result = 0;
    int sub_len = pkt_len - str_len;
    for (i = 0; i < sub_len; ++i)
    {
        for (j = 0; j < str_len; ++j)
        {
            if (*(pkt_data + i + j) != *(str + j)) break;

        }
        if (j == str_len)
        {
            for (j = 0; j < str_len; ++j)
            {
                *(pkt_data + i + j) = *(replace + j);

            }
            result = 1;
        }
    }
    return result;
}