#ifndef FILE_PROCESS_H
#define FILE_PROCESS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

FILE *open_file(const char *file_name, const char *mode);
char *read_file(FILE* file);
void write_to_file(FILE* file, const char* content);
void insert_word_at_position(const char* filename,const char* word,long position);
int find_end_position_of_second_number(const char *line);
void printf_json_in_file(const char *output_file,const char *json_string);
void printf_time_to_file(const char *file_name);
void printf_time_to_file_custom(FILE *file) ;
void clear_file_to_run(const char *filename);

#endif