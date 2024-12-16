
#include <stdbool.h>
#ifndef PARSERS_DATA_H
#define PARSERS_DATA_H

#define MAX_LENGTH 256
#define MAX_TIME_LENGTH 20

typedef struct {
    char url[MAX_LENGTH];
    char start_day[MAX_LENGTH];
    char start_time[MAX_LENGTH];
    char end_day[MAX_LENGTH];
    char end_time[MAX_LENGTH];
} website_block;


typedef struct {
    char time[MAX_LENGTH];
    char date[MAX_LENGTH];
    char url[MAX_LENGTH];
    char ip[MAX_LENGTH];
} website_info;

typedef struct {
    char url[MAX_LENGTH];
    char ip[MAX_LENGTH];
    char start_day[MAX_LENGTH];
    char start_time[MAX_LENGTH];
    char end_day[MAX_LENGTH];
    char end_time[MAX_LENGTH];

} web_block_info;

typedef struct {
    char url[MAX_LENGTH];
    long start_time_block;
    long end_time_block;

} check;

typedef struct {
    char file_name[MAX_LENGTH];
    char domain_name[MAX_LENGTH];
    char file_path[MAX_LENGTH];
} domain_file;

website_block* read_block_web(const char *filename, int *line_count);
web_block_info* read_web_block_info(const char *filename, int *count);
check* read_check_list(const char *filename, int *count);
void printf_to_file(const char *filename);
void printf_ip_and_time_to_console();
void check_and_print_access_pages(const char* filename);
bool is_line_in_file(FILE *file, const char *line);
#endif // PARSERS_DATA_H