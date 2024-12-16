#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <string.h>
#include <file_process.h>
#include "dns.h"
#include "packet_process.h"
#include "log.h"
#include "parsers_data.h"

#define ONE_BYTE 1
#define TWO_BYTE 2
#define FOUR_BYTE 4
#define EIGHT_BYTE 8

// #define FILE_DATA "./data/data.txt"

#define FILE_DATA "../../block_app/data/data.txt"

#define BLOCK_WEB_TXT_PATH "../../block_app/data/block_web.txt"

#define LIST_DOMAIN_FILE_PATH "../../block_app/data/list_domain_file.txt"

#define DOMAIN_FOLDER "../block_app/domain"

typedef struct
{
    char domain[256];
    char ip_address[16];
} record;

record *recorded_list = NULL;
size_t recorded_count = 0;
size_t recorded_capacity = 0;

#include <stdio.h>
#include <string.h>


void add_record(const char *domain, const char *ip_address)
{
    if (recorded_count == recorded_capacity)
    {
        recorded_capacity = (recorded_capacity == 0) ? 10 : recorded_capacity * 2;
        recorded_list = realloc(recorded_list, recorded_capacity * sizeof(record));
        if (!recorded_list)
        {
            fprintf(stderr, "Unable to allocate memory!\n");
            exit(1);
        }
    }
    strncpy(recorded_list[recorded_count].domain, domain, sizeof(recorded_list[recorded_count].domain) - 1);
    strncpy(recorded_list[recorded_count].ip_address, ip_address, sizeof(recorded_list[recorded_count].ip_address) - 1);
    recorded_count++;
}

bool is_recorded(const char *domain, const char *ip_address)
{
    for (size_t i = 0; i < recorded_count; i++)
    {
        if (strcmp(recorded_list[i].domain, domain) == 0 &&
            strcmp(recorded_list[i].ip_address, ip_address) == 0)
        {
            return true;
        }
    }
    return false;
}

void clear_file_to_start()
{
    FILE *file = fopen(FILE_DATA, "w");
    if (file == NULL)
    {
        fclose(file);
    }
}

int get_dns_query_length(unsigned char *dns_query)
{
    int name_length = 0;
    while (dns_query[name_length] != 0)
    {
        name_length += dns_query[name_length] + ONE_BYTE;
    }
    return name_length + ONE_BYTE + FOUR_BYTE;
}

int get_dns_answer_length(unsigned char *dns_answer)
{
    int name_length = 0;
    if ((dns_answer[0] & 0xC0) == 0xC0)
    {
        name_length = TWO_BYTE;
    }
    else
    {
        while (dns_answer[name_length] != 0)
        {
            name_length += dns_answer[name_length] + ONE_BYTE;
        }
        name_length += ONE_BYTE;
    }

    unsigned short type = ntohs(*(unsigned short *)(dns_answer + name_length));
    unsigned short class = ntohs(*(unsigned short *)(dns_answer + name_length + TWO_BYTE));
    unsigned int ttl = ntohl(*(unsigned int *)(dns_answer + name_length + FOUR_BYTE));
    unsigned short data_len = ntohs(*(unsigned short *)(dns_answer + name_length + 8));
    int total_length = name_length + TWO_BYTE + TWO_BYTE + FOUR_BYTE + TWO_BYTE + data_len;

    return total_length;
}

void decode_dns_name(unsigned char *dns, unsigned char *buffer, int *offset)
{
    int i = 0, j = 0;
    while (dns[i] != 0)
    {
        int len = dns[i];
        for (j = 0; j < len; j++)
        {
            buffer[*offset + j] = dns[i + 1 + j];
        }
        *offset += len;
        buffer[*offset] = '.';
        *offset += 1;
        i += len + 1;
    }
    buffer[*offset - 1] = '\0';
}

void printf_dns_query(unsigned char *dns_query)
{
    unsigned char decode_name[256];
    int offset = 0;
    decode_dns_name(dns_query, decode_name, &offset);
    printf("QNAME: %s\n", decode_name);
    int qname_length = get_dns_query_length(dns_query) - 4;
    unsigned short qtype = ntohs(*(unsigned short *)(dns_query + qname_length));
    unsigned short qclass = ntohs(*(unsigned short *)(dns_query + qname_length + TWO_BYTE));
    printf("QTYPE: %u\n", qtype);
    printf("QCLASS: %u\n", qclass);
}

void decode_dns_name_answer(unsigned char *dns_packet, unsigned char *buffer, int *offset, int start)
{
    int i = start;
    int j = 0;
    int jumped = 0;
    int jump_offset = 0;

    while (dns_packet[i] != 0)
    {
        if ((dns_packet[i] & 0xC0) == 0xC0)
        {
            if (!jumped)
            {
                jump_offset = i + 2;
            }
            jumped = 1;
            int pointer_offset = ((dns_packet[i] & 0x3F) << 8) | dns_packet[i + 1];
            i = pointer_offset;
        }
        else
        {
            int len = dns_packet[i];
            i += 1;
            for (int k = 0; k < len; k++)
            {
                buffer[j++] = dns_packet[i + k];
            }
            buffer[j++] = '.';
            i += len;
        }
    }
    buffer[j - 1] = '\0';
    if (jumped)
    {
        *offset = jump_offset;
    }
    else
    {
        *offset = i + 1;
    }
}

unsigned char *get_dns_answer_name(unsigned char *dns_packet, int answer_offset)
{
    unsigned char *decoded_name = malloc(256);
    if (decoded_name == NULL)
    {
        printf("Memory allocation failed\n");
        return NULL;
    }
    int offset = 0;
    decode_dns_name_answer(dns_packet, decoded_name, &offset, answer_offset);
    return decoded_name;
}

void create_file_if_not_exists(unsigned char *folder, const char *domain_name) {
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/%s.txt", (char*)folder, domain_name);
    FILE *file = fopen(filepath, "a+");
    if (file == NULL) {
        fprintf(stderr, "Unable to create or open file: %s\n", filepath);
        return;
    }
    fclose(file);
}

bool is_ip_in_file(const unsigned char *folder, const char *domain_name, const char* ip_str) {
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/%s.txt", folder, domain_name);
    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        fprintf(stderr, "Unable to open file: %s\n", filepath);
        return false;
    }
    char line[512];
    bool ip_found = false;
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, ip_str)) {
            ip_found = true;
            break;
        }
    }
    fclose(file);
    return ip_found;
}

void printf_dns_answer_to_file(unsigned char *dns_answer, unsigned char *dns_payload_content, unsigned char *filename)
{
    int answer_offset = 0;
    int name_length = 0;
    if ((dns_answer[0] & 0xC0) == 0xC0)
    {
        name_length = 2;
    }
    else
    {
        while (dns_answer[name_length] != 0)
        {
            name_length += dns_answer[name_length] + 1;
        }
        name_length += 1;
    }

    unsigned short type = ntohs(*(unsigned short *)(dns_answer + name_length));
    unsigned short data_len = ntohs(*(unsigned short *)(dns_answer + name_length + 8));

    FILE *file = fopen(filename, "a");
    if (file != NULL)
    {
        if (type == 1 && data_len == 4)
        {
            struct in_addr ipv4_addr;
            memcpy(&ipv4_addr, dns_answer + name_length + 10, sizeof(ipv4_addr));

            char *domain_name = get_dns_answer_name(dns_payload_content, answer_offset);
            char *ip_str = inet_ntoa(ipv4_addr);
            int num_struct = 0;
            website_block *list = read_block_web(BLOCK_WEB_TXT_PATH, &num_struct);
            for (int i = 0; i < num_struct; i++)
            {
                if (strcmp((char *)list[i].url, domain_name) == 0)
                {
                    if (!is_recorded(domain_name, ip_str))
                    {
                        printf_time_to_file(FILE_DATA);
                        fprintf(file, "Name: %s\n", domain_name);
                        fprintf(file, "IPv4 Address: %s\n", ip_str);
                        fprintf(file, "--------------------------------\n");
                        add_record(domain_name, ip_str);
                    }
                }
            }
        }
        fclose(file);
    }
    else
    {
        fprintf(stderr, "Unable to open file\n");
    }
}

bool is_line_have_in_file(FILE *file, const char *line)
{
    char buffer[256];
    rewind(file);
    while (fgets(buffer, sizeof(buffer), file) != NULL)
    {
        buffer[strcspn(buffer, "\n")] = '\0';

        if (strcmp(buffer, line) == 0)
        {
            return true;
        }
    }
    return false;
}

void printf_dns_answer_to_folder_and_file(unsigned char *dns_answer, unsigned char *dns_payload_content, unsigned char *folder)
{
    int answer_offset = 0;
    int name_length = 0;

    if ((dns_answer[0] & 0xC0) == 0xC0)
    {
        name_length = 2;
    }
    else
    {
        while (dns_answer[name_length] != 0)
        {
            name_length += dns_answer[name_length] + 1;
        }
        name_length += 1;
    }
    unsigned short type = ntohs(*(unsigned short *)(dns_answer + name_length));
    unsigned short data_len = ntohs(*(unsigned short *)(dns_answer + name_length + 8));
    if (type == 1 && data_len == 4)
    {
        struct in_addr ipv4_addr;
        memcpy(&ipv4_addr, dns_answer + name_length + 10, sizeof(ipv4_addr));
        char *domain_name = get_dns_answer_name(dns_payload_content, answer_offset);
        char *ip_str = inet_ntoa(ipv4_addr);
        int num_struct = 0;
        website_block *list = read_block_web(BLOCK_WEB_TXT_PATH, &num_struct);
        int is_match = 0;
        for (int i = 0; i < num_struct; i++)
        {
            if (strcmp((char *)list[i].url, domain_name) == 0)
            {
                is_match = 1;
                break;
            }
        }
        if (!is_match)
        {
            return;
        }
        create_file_if_not_exists(folder,domain_name);
        char filepath[512];
        snprintf(filepath, sizeof(filepath), "%s/%s.txt", (char *)folder, domain_name);
        if(!is_ip_in_file(folder,domain_name,ip_str)){
            FILE *file = fopen(filepath, "a+");
            if (file == NULL) {
                fprintf(stderr, "Unable to create or open file: %s\n", filepath);
                return;
            }
            char buffer[512];
            snprintf(buffer, sizeof(buffer), "Name: %s\nIPv4 Address: %s", domain_name, ip_str);
            printf_time_to_file_custom(file);
            fprintf(file, "%s\n--------------------------------\n", buffer);
            fclose(file);
        }


        char list_file_path[512];
        snprintf(list_file_path, sizeof(list_file_path), LIST_DOMAIN_FILE_PATH);
        FILE *list_file = fopen(list_file_path, "a+");
        if (list_file == NULL)
        {
            fprintf(stderr, "Unable to create or open file: %s\n", list_file_path);
            return;
        }
        char list_entry[512];
        snprintf(list_entry, sizeof(list_entry), "%s,%s,%s", strrchr(filepath, '/') + 1, domain_name, filepath);
        if (!is_line_have_in_file(list_file, list_entry))
        {
            fprintf(list_file, "%s\n", list_entry);
        }
        fclose(list_file);
    }
}
