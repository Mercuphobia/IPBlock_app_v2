#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <dirent.h>
#include <sys/stat.h> 
#include "log.h"
#include "parsers_data.h"

// run board//
#define IPSET_LIST_NO_STDOUT "/userfs/bin/ipset list %s > /dev/null 2>&1"
#define IPSET_CREATE "/userfs/bin/ipset create %s hash:ip"
#define IPSET_ADD "/userfs/bin/ipset add %s %s"
#define IPSET_DELETE_RULE "/userfs/bin/ipset destroy %s_%ld > /dev/null 2>&1"
#define IPSET_TEST_RULE "/userfs/bin/ipset test %s %s > /dev/null 2>&1"
#define IPSET_CREATE_NET "/userfs/bin/ipset create %s hash:net"
#define IPSET_DELETE_RULE_NET "/userfs/bin/ipset destroy %s > /dev/null 2>&1"

// run vmware//
// #define IPSET_LIST_NO_STDOUT "ipset list %s > /dev/null 2>&1"
// #define IPSET_CREATE "ipset create %s hash:ip"
// #define IPSET_ADD "ipset add %s %s"
// #define IPSET_DELETE_RULE "ipset destroy %s_%ld > /dev/null 2>&1"
// #define IPSET_TEST_RULE "ipset test %s %s > /dev/null 2>&1"
// #define IPSET_CREATE_NET "ipset create %s hash:net"
// #define IPSET_DELETE_RULE_NET "ipset destroy %s > /dev/null 2>&1"



// #define IP_TABLES_ADD_INPUT "iptables -I INPUT -m set --match-set %s_%ld src -j DROP"
// #define IP_TABLES_ADD_OUTPUT "iptables -I OUTPUT -m set --match-set %s_%ld src -j DROP"
// #define IP_TABLES_ADD_FORWARD "iptables -I FORWARD -m set --match-set %s_%ld src -j DROP"

#define IP_TABLES_DELETE_INPUT "iptables -D INPUT -m set --match-set %s_%ld src -j DROP 2>/dev/null"
#define IP_TABLES_DELETE_OUTPUT "iptables -D OUTPUT -m set --match-set %s_%ld src -j DROP 2>/dev/null"
#define IP_TABLES_DELETE_FORWARD "iptables -D FORWARD -m set --match-set %s_%ld src -j DROP 2>/dev/null"


#define RULE_CREATE_CHAIN "iptables -N BLOCK_IP_CHAIN"
#define CHECK_NAME_CHAIN "iptables -L BLOCK_IP_CHAIN >/dev/null 2>&1"
#define CHECK_BLOCK_IP_CHAIN_INPUT "iptables -L INPUT | grep -q BLOCK_IP_CHAIN"
#define CHECK_BLOCK_IP_CHAIN_OUTPUT "iptables -L OUTPUT | grep -q BLOCK_IP_CHAIN"
#define CHECK_BLOCK_IP_CHAIN_FORWARD "iptables -L FORWARD | grep -q BLOCK_IP_CHAIN"

#define IP_TABLES_ADD_CHAIN_INPUT "iptables -A INPUT -j BLOCK_IP_CHAIN"
#define IP_TABLES_ADD_CHAIN_OUTPUT "iptables -A OUTPUT -j BLOCK_IP_CHAIN"
#define IP_TABLES_ADD_CHAIN_FORWARD "iptables -A FORWARD -j BLOCK_IP_CHAIN"



#define IP_TXT_PATH "../../block_app/data/ip.txt"
#define CHECK_TXT_PATH "../../block_app/data/check.txt"
#define DOMAIN_NAME_TXT_PATH "../../block_app/data/domain_name.txt"
#define IP_DB_DIR "../../block_app/ip_db"



#define REST_TIME_BETWEEN_RUN 30
#define MAX_PATH_LENGTH 1024
#define MAX_IP_LENGTH 64
int num_struct = 0;
char command[256];

int get_day_number(const char *day)
{
    if (strcmp(day, "Monday") == 0)
        return 0;
    if (strcmp(day, "Tuesday") == 0)
        return 1;
    if (strcmp(day, "Wednesday") == 0)
        return 2;
    if (strcmp(day, "Thursday") == 0)
        return 3;
    if (strcmp(day, "Friday") == 0)
        return 4;
    if (strcmp(day, "Saturday") == 0)
        return 5;
    if (strcmp(day, "Sunday") == 0)
        return 6;
    return -1;
}

long convert_to_seconds(const char *day, const char *time)
{
    int day_number = get_day_number(day);
    if (day_number == -1)
    {
        printf("Invalid day: %s\n", day);
        return -1;
    }
    int hours, minutes;
    sscanf(time, "%d:%d", &hours, &minutes);
    long total_seconds = day_number * 86400 + hours * 3600 + minutes * 60;
    return total_seconds;
}

long get_current_time_in_seconds()
{
    time_t now = time(NULL);
    struct tm *tm_now = localtime(&now);
    int day_number = tm_now->tm_wday - 1;
    if (day_number < 0)
        day_number = 6;
    long total_seconds = day_number * 86400 + tm_now->tm_hour * 3600 + tm_now->tm_min * 60 + tm_now->tm_sec;
    return total_seconds;
}

int ipset_exists(const char *ipset_name)
{
    snprintf(command, sizeof(command), IPSET_LIST_NO_STDOUT, ipset_name);
    int result = system(command);
    return result == 0;
}

void create_ipset(const char *ipset_name)
{
    if (!ipset_exists(ipset_name))
    {
        snprintf(command, sizeof(command), IPSET_CREATE, ipset_name);
        system(command);
    }
}


void add_ipset_to_chain(const char *ipset_name)
{
    //snprintf(command, sizeof(command), "iptables -C BLOCK_IP_CHAIN -m set --match-set %s src -j DROP 2>/dev/null", ipset_name);
    snprintf(command, sizeof(command), "iptables -S BLOCK_IP_CHAIN | grep -q -- '-m set --match-set %s src -j DROP'", ipset_name);
    if (system(command) != 0) {
        snprintf(command, sizeof(command), "iptables -A BLOCK_IP_CHAIN -m set --match-set %s src -j DROP", ipset_name);
        system(command);
        printf("Added ipset %s to BLOCK_IP_CHAIN with DROP action.\n", ipset_name);
    }
}

void delete_ipset_to_chain(const char *ipset_name) {
    //snprintf(command, sizeof(command), "iptables -C BLOCK_IP_CHAIN -m set --match-set %s src -j DROP 2>/dev/null", ipset_name);
    snprintf(command, sizeof(command), "iptables -S BLOCK_IP_CHAIN | grep -q -- '-m set --match-set %s src -j DROP'", ipset_name);
    if (system(command) == 0) {
        snprintf(command, sizeof(command), "iptables -D BLOCK_IP_CHAIN -m set --match-set %s src -j DROP", ipset_name);
        system(command);
        printf("Removed ipset %s from BLOCK_IP_CHAIN with DROP action.\n", ipset_name);
    }
}

void add_ip_to_ipset(const char *ipset_name, const char *ip)
{
    snprintf(command, sizeof(command), IPSET_TEST_RULE, ipset_name, ip);
    if (system(command) != 0)
    {
        snprintf(command, sizeof(command), IPSET_ADD, ipset_name, ip);
        system(command);
    }
}


int rule_iptables_exists(const char *url, long start_time)
{
    snprintf(command, sizeof(command), "iptables -L | grep -q %s_%ld", url, start_time);
    return system(command) == 0;
}


void get_list()
{
    web_block_info *list = read_web_block_info(IP_TXT_PATH, &num_struct);
    FILE *check_file = fopen(CHECK_TXT_PATH, "a+");
    if (check_file == NULL)
    {
        printf("Unable to open file\n");
        return;
    }
    for (int i = 0; i < num_struct; i++)
    {   
        time_t current_time = time(NULL);
        long local_time = get_current_time_in_seconds();
        long start_block_time = convert_to_seconds(list[i].start_day, list[i].start_time);
        long end_block_time = convert_to_seconds(list[i].end_day, list[i].end_time);
        char line[256];
        snprintf(line, sizeof(line), "%s, %ld, %ld\n", list[i].url, start_block_time, end_block_time);
        if (!is_line_in_file(check_file, line))
        {
            fprintf(check_file, "%s", line);
        }
        // extra
        char ipset_name[256];
        if(start_block_time < end_block_time){
            if(local_time < start_block_time || local_time > end_block_time){
                snprintf(ipset_name, sizeof(ipset_name), "%s_%ld", list[i].url, start_block_time);
                if (ipset_exists(ipset_name))
                {
                    snprintf(command, sizeof(command), IPSET_DELETE_RULE, list[i].url, start_block_time);
                    system(command);
                    delete_ipset_to_chain(ipset_name);
                }
            }
            else if(local_time >= start_block_time && local_time <= end_block_time){
                snprintf(ipset_name, sizeof(ipset_name), "%s_%ld", list[i].url, start_block_time);
                create_ipset(ipset_name);
                add_ipset_to_chain(ipset_name);
                add_ip_to_ipset(ipset_name, list[i].ip);
            }
        }
        else {
            if(local_time < start_block_time && local_time > end_block_time){
                snprintf(ipset_name, sizeof(ipset_name), "%s_%ld", list[i].url, start_block_time);
                if (ipset_exists(ipset_name))
                {
                    snprintf(command, sizeof(command), IPSET_DELETE_RULE, list[i].url, start_block_time);
                    system(command);
                    delete_ipset_to_chain(ipset_name);
                }
            }
            else if(local_time >= start_block_time && local_time > end_block_time){
                snprintf(ipset_name, sizeof(ipset_name), "%s_%ld", list[i].url, start_block_time);
                create_ipset(ipset_name);
                add_ipset_to_chain(ipset_name);
                add_ip_to_ipset(ipset_name, list[i].ip);
            }
            else if(local_time < start_block_time && local_time <= end_block_time){
                snprintf(ipset_name, sizeof(ipset_name), "%s_%ld", list[i].url, start_block_time);
                create_ipset(ipset_name);
                add_ipset_to_chain(ipset_name);
                add_ip_to_ipset(ipset_name, list[i].ip);
            }
        }

        // if(start_block_time > end_block_time){
        //     if(local_time >= start_block_time && local_time > end_block_time){
        //         snprintf(ipset_name, sizeof(ipset_name), "%s_%ld", list[i].url, convert_to_seconds(list[i].start_day,list[i].start_time));
        //         create_ipset(ipset_name);
        //         add_ipset_to_chain(ipset_name);
        //         add_ip_to_ipset(ipset_name, list[i].ip);
        //     }
        //     else if()
        // }
        // else{

        // }
        // if(local_time < start_block_time || local_time > end_block_time){
        //     snprintf(ipset_name, sizeof(ipset_name), "%s_%ld", list[i].url, convert_to_seconds(list[i].start_day,list[i].start_time));
        //     if (ipset_exists(ipset_name))
        //     {
        //         snprintf(command, sizeof(command), IPSET_DELETE_RULE, list[i].url, start_block_time);
        //         system(command);
        //         delete_ipset_to_chain(ipset_name);
        //     }
        // }
        // else if(local_time >= start_block_time && local_time <= end_block_time){
        //     snprintf(ipset_name, sizeof(ipset_name), "%s_%ld", list[i].url, convert_to_seconds(list[i].start_day,list[i].start_time));
        //     create_ipset(ipset_name);
        //     add_ipset_to_chain(ipset_name);
        //     add_ip_to_ipset(ipset_name, list[i].ip);
        // }
        // else if(local_time >= start_block_time && local_time > end_block_time){
        //     snprintf(ipset_name, sizeof(ipset_name), "%s_%ld", list[i].url, convert_to_seconds(list[i].start_day,list[i].start_time));
        //     create_ipset(ipset_name);
        //     add_ipset_to_chain(ipset_name);
        //     add_ip_to_ipset(ipset_name, list[i].ip);
        // }
        // else {
        //     snprintf(ipset_name, sizeof(ipset_name), "%s_%ld", list[i].url, convert_to_seconds(list[i].start_day,list[i].start_time));
        //     if (ipset_exists(ipset_name))
        //     {
        //         snprintf(command, sizeof(command), IPSET_DELETE_RULE, list[i].url, start_block_time);
        //         system(command);
        //         delete_ipset_to_chain(ipset_name);
        //         //printf("start_time_block: %ld\n",start_block_time);
        //     }
        // }
        

        // end extra
    }
    fclose(check_file);
}


void delete_iptable_rules_chain_and_ipset()
{
    LOG(LOG_LVL_ERROR, "test_delete_iptable_rules_chain_and_ipset: %s, %s, %d\n", __FILE__, __func__, __LINE__);
    check *list = read_check_list(CHECK_TXT_PATH, &num_struct);
    for (int i = 0; i < num_struct; i++)
    {
        char name_ipset[256];
        snprintf(name_ipset, sizeof(name_ipset), "%s_%ld", list[i].url, list[i].start_time_block);
        if (ipset_exists(name_ipset))
        {
            snprintf(command, sizeof(command), IP_TABLES_DELETE_INPUT, list[i].url, list[i].start_time_block);
            system(command);
            snprintf(command, sizeof(command), IP_TABLES_DELETE_OUTPUT, list[i].url, list[i].start_time_block);
            system(command);
            snprintf(command, sizeof(command), IP_TABLES_DELETE_FORWARD, list[i].url, list[i].start_time_block);
            system(command);
            snprintf(command, sizeof(command), IPSET_DELETE_RULE, list[i].url, list[i].start_time_block);
            system(command);
        }
        else
        {
            printf("ipset %s_%ld does not exist.\n", list[i].url, list[i].start_time_block);
        }
    }
}

void create_and_add_chain(){
    if (system(CHECK_NAME_CHAIN) != 0) {
        system(RULE_CREATE_CHAIN);
    }
    if (system(CHECK_BLOCK_IP_CHAIN_INPUT) != 0) {
        system(IP_TABLES_ADD_CHAIN_INPUT);
        printf("Added BLOCK_IP_CHAIN to INPUT chain.\n");
    }
    if (system(CHECK_BLOCK_IP_CHAIN_OUTPUT) != 0) {
        system(IP_TABLES_ADD_CHAIN_OUTPUT);
        printf("Added BLOCK_IP_CHAIN to OUTPUT chain.\n");
    }
    if (system(CHECK_BLOCK_IP_CHAIN_FORWARD) != 0) {
        system(IP_TABLES_ADD_CHAIN_FORWARD);
        printf("Added BLOCK_IP_CHAIN to FORWARD chain.\n");
    }
}

int find_file_in_directory(const char *dir_path, const char *filename, char *found_path) {
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
                if (find_file_in_directory(full_path, filename, found_path)) {
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

void create_ipset_in_file(char *filename){
    if (!ipset_exists(filename))
    {
        snprintf(command, sizeof(command), IPSET_CREATE_NET, filename);
        system(command);
    }
}


void run_command(const char *command) {
    int ret = system(command);
    if (ret != 0) {
        fprintf(stderr, "Command failed: %s\n", command);
    }
}

void add_list_ip_from_file(char *filepath, char *filename) {
    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        perror("Unable to open file");
        return;
    }
    char ip[MAX_IP_LENGTH];
    while (fgets(ip, sizeof(ip), file)) {
        ip[strcspn(ip, "\n")] = '\0';
        ip[strcspn(ip, "\r")] = '\0';
        snprintf(command, sizeof(command), IPSET_TEST_RULE, filename, ip);
        int ret = system(command);
        if (ret != 0) {
            snprintf(command, sizeof(command), IPSET_ADD, filename, ip);
            run_command(command);
        }
    }
    fclose(file);
}


void create_and_add_ipset_ip_db(char *filename, char* filepath){
    check *list = read_check_list(DOMAIN_NAME_TXT_PATH, &num_struct);
    for(int i=0;i<num_struct;i++){
        time_t current_time = time(NULL);
        long local_time = get_current_time_in_seconds();
        long start_block_time = list[i].start_time_block;
        long end_block_time = list[i].end_time_block;
        char ipset_name[256];
        if(start_block_time < end_block_time){
            if(local_time < start_block_time || local_time > end_block_time){
                if(strcmp(filename, list[i].url) == 0){
                    snprintf(ipset_name, sizeof(ipset_name), "%s_%ld", list[i].url,start_block_time);
                    if (ipset_exists(ipset_name))
                    {
                        snprintf(command, sizeof(command), IPSET_DELETE_RULE, list[i].url, start_block_time);
                        system(command);
                        delete_ipset_to_chain(ipset_name);
                    }
                }
            }
            else if(local_time >= start_block_time && local_time < end_block_time){
                if(strcmp(filename,list[i].url) == 0){
                    snprintf(ipset_name, sizeof(ipset_name), "%s_%ld", list[i].url, start_block_time);
                    create_ipset_in_file(ipset_name);
                    add_ipset_to_chain(ipset_name);
                    add_list_ip_from_file(filepath,ipset_name);
                }
            }
        }
        else{
            if(local_time < start_block_time && local_time > end_block_time){
                if(strcmp(filename, list[i].url) == 0){
                    snprintf(ipset_name, sizeof(ipset_name), "%s_%ld", list[i].url,start_block_time);
                    if (ipset_exists(ipset_name))
                    {
                        snprintf(command, sizeof(command), IPSET_DELETE_RULE, list[i].url, start_block_time);
                        system(command);
                        delete_ipset_to_chain(ipset_name);
                    }
                }
            }
            else if(local_time >= start_block_time && local_time > end_block_time){
                if(strcmp(filename,list[i].url) == 0){
                    snprintf(ipset_name, sizeof(ipset_name), "%s_%ld", list[i].url, start_block_time);
                    create_ipset_in_file(ipset_name);
                    add_ipset_to_chain(ipset_name);
                    add_list_ip_from_file(filepath,ipset_name);
                }
            }
            else if(local_time < start_block_time && local_time <= end_block_time){
                if(strcmp(filename,list[i].url) == 0){
                    snprintf(ipset_name, sizeof(ipset_name), "%s_%ld", list[i].url, start_block_time);
                    create_ipset_in_file(ipset_name);
                    add_ipset_to_chain(ipset_name);
                    add_list_ip_from_file(filepath,ipset_name);
                }
            }
        }
    }
}


void run_block_ip()
{
    create_and_add_chain();
    int num_web = 0;
    check *list = read_check_list(DOMAIN_NAME_TXT_PATH,&num_web);
    for(int i=0;i<num_web;i++){
        char file_path[MAX_PATH_LENGTH];
        if (find_file_in_directory(IP_DB_DIR, list[i].url, file_path)) {
            create_and_add_ipset_ip_db(list[i].url,file_path);
        }
    }
    check_and_print_access_pages(IP_TXT_PATH);
    get_list();
    //printf_to_file(IP_TXT_PATH);
    //get_list();
}