#ifndef DNS_H
#define DNS_H

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

struct dns_header {
    unsigned short id;       
    unsigned short flags;    
    unsigned short qdcount;  
    unsigned short ancount;  
    unsigned short nscount;  
    unsigned short arcount;  
};

struct dns_queries {
    unsigned short qname;   
    unsigned short qtype;    
    unsigned short qclass;   
};

struct dns_answer {
    unsigned short name;
    unsigned short type;     
    unsigned short class;    
    unsigned int ttl;        
    unsigned short data_len; 
    unsigned int ip_addr;    
};

void clear_file_to_start();
int get_dns_query_length(unsigned char *dns_query);
int get_dns_answer_length(unsigned char *dns_answer);
void decode_dns_name(unsigned char *dns, unsigned char *buffer, int *offset);
void printf_dns_query(unsigned char *dns_query);
void decode_dns_name_answer(unsigned char *dns_packet, unsigned char *buffer, int *offset, int start);
unsigned char *get_dns_answer_name(unsigned char *dns_packet, int answer_offset);
void printf_dns_answer_to_file(unsigned char *dns_answer, unsigned char* dns_payload_content, unsigned char* filename);
void printf_dns_answer_to_folder_and_file(unsigned char *dns_answer, unsigned char *dns_payload_content, unsigned char *folder);
void printf_dns_answer_to_console(unsigned char *dns_answer, unsigned char* dns_payload_content);
static u_int32_t process_packet(struct nfq_data *tb);
bool is_line_have_in_file(FILE *file, const char *line);


// extra
void free_recorded_list();

#endif
