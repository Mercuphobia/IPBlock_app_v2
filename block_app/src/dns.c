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
#include <dirent.h>
#include <sys/stat.h>
#include <file_process.h>
#include "dns.h"
#include "packet_process.h"
#include "log.h"
#include "parsers_data.h"

#define ONE_BYTE 1
#define TWO_BYTE 2
#define FOUR_BYTE 4
#define EIGHT_BYTE 8

#define MAX_PATH_LENGTH 1024

// #define FILE_DATA "./data/data.txt"

#define FILE_DATA "../../block_app/data/data.txt"

#define BLOCK_WEB_TXT_PATH "../../block_app/data/block_web.txt"

#define LIST_DOMAIN_FILE_PATH "../../block_app/data/list_domain_file.txt"

#define DOMAIN_FOLDER "../block_app/domain"


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

int find_file_in_subfolders(const char *dir_path, const char *filename, char *found_path) {
    DIR *dir = opendir(dir_path);
    if (dir == NULL) {
        perror("Unable to open directory");
        return 0;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        char full_path[MAX_PATH_LENGTH];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        struct stat statbuf;
        if (stat(full_path, &statbuf) == 0) {
            if (S_ISDIR(statbuf.st_mode)) {
                if (find_file_in_subfolders(full_path, filename, found_path)) {
                    closedir(dir);
                    return 1;
                }
            } else if (S_ISREG(statbuf.st_mode)) {
                if (strcmp(entry->d_name, filename) == 0) {
                    snprintf(found_path, MAX_PATH_LENGTH, "%s", full_path);
                    closedir(dir);
                    return 1;
                }
            }
        }
    }
    closedir(dir);
    return 0;
}

void create_file_if_not_exists_in_folder(const char *folder, const char *website_name) {
    char result_path[512];
    if (!find_file_in_subfolders(folder, website_name, result_path)) {
        char filepath[512];
        snprintf(filepath, sizeof(filepath), "%s/other/%s", folder, website_name);
        FILE *file = fopen(filepath, "a+");
        if (file == NULL) {
            fprintf(stderr, "Unable to create file: %s\n", filepath);
            return;
        }
        fclose(file);
    }
}

void write_ip_to_file(const char *website_name, const char *file_path, const char *ip_str) {
    FILE *file = fopen(file_path, "a+");
    if (file == NULL) {
        fprintf(stderr, "Unable to open file: %s\n", file_path);
        return;
    }
    fseek(file, 0, SEEK_SET);
    char line[512];
    bool ip_found = false;
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, ip_str)) {
            ip_found = true;
            break;
        }
    }
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    if (!ip_found) {
        if (file_size > 0) {
            fprintf(file, "\n%s", ip_str);
        } else {
            fprintf(file, "%s", ip_str);
        }
    }

    fclose(file);
}

char* get_website_name_from_domain_name(const char *domain_name){
    char buffer[256];
    char *token, *name = NULL;
    strncpy(buffer, domain_name, sizeof(buffer)-1);
    buffer[sizeof(buffer) - 1] = '\0';
    if (strncmp(buffer, "http://", 7) == 0) {
        token = strtok(buffer + 7, "/");
    } else if (strncmp(buffer, "https://", 8) == 0) {
        token = strtok(buffer + 8, "/");
    } else {
        token = strtok(buffer, "/");
    }
    if (token != NULL && strncmp(token, "www.", 4) == 0) {
        token += 4;
    }
    if (token != NULL) {
        char *dot = strchr(token, '.');
        if (dot != NULL) {
            *dot = '\0';
        }
        name = token;
    }
    return name;

}

void printf_ip_to_db(unsigned char *dns_answer, unsigned char *dns_payload_content, unsigned char *folder_path){
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
        for(int i=0;i<num_struct;i++){
            if(strstr(domain_name, (char *)list[i].url) != NULL){
                char *web_name = get_website_name_from_domain_name(list[i].url);
                create_file_if_not_exists_in_folder(folder_path, web_name);
                char file_path_in_folder[512];
                if(find_file_in_subfolders(folder_path, web_name, file_path_in_folder)){
                    write_ip_to_file(web_name, file_path_in_folder, ip_str);
                }
            }
        }
        
    }
}