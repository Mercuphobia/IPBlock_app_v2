#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include "log.h"



FILE *open_file(const char *file_name, const char *mode){
    FILE *file = fopen(file_name,mode);
    if(!file){
        perror("Open file false");
    }
    return file;
}

char *read_file(FILE* file){
    if(file == NULL){
        return NULL;
    }

    fseek(file,0,SEEK_END);
    long long filesize = ftell(file);
    rewind(file);

    char* content = (char*)malloc(sizeof(char)* (filesize+1));
    if(content == NULL){
        perror("Failed to allocate memory");
        return NULL;
    }
    fread(content,sizeof(char),filesize,file);
    content[filesize] = '\0';
    return content;
}

void write_to_file(FILE* file, const char* content){
    if(file == NULL){
        return;
    }
    fprintf(file,"%s",content);  
}

void insert_word_at_position(const char* filename,const char* word,long position){
    FILE *file = open_file(filename,"r+");
    if(file == NULL){
        return;
    }

    fseek(file,0,SEEK_END);
    long long filesize = ftell(file);
    rewind(file);

    char *content = (char *)malloc(filesize+1);
    if(content == NULL){
        perror("Failed to allocte memory");
        fclose(file);
        return;
    }

    fread(content,sizeof(char),filesize,file);
    content[filesize] = '\0';

    long new_size = filesize + strlen(word);
    char *new_content = (char *)malloc(new_size + 1);
    if(new_content == NULL){
        perror("Failed to allocate memory");
        free(content);
        fclose(file);
        return;
    }

    strncpy(new_content,content,position);
    strcpy(new_content + position, word);
    strcpy(new_content + position + strlen(word),content + position);

    new_content[new_size] = '\0';

    freopen(filename,"w",file);
    fwrite(new_content,sizeof(char),new_size,file);

    free(content);
    free(new_content);
    fclose(file);

}


int find_end_position_of_second_number(const char *line) {
    int num1, num2;
    const char *ptr = line;
    
    if (sscanf(ptr, "%d %d", &num1, &num2) == 2) {
        while (*ptr && !isspace(*ptr)) {
            ptr++;
        }
        while (*ptr && isspace(*ptr)) {
            ptr++;
        }
        while (*ptr && !isspace(*ptr)) {
            ptr++;
        }
        while (*ptr && !isspace(*ptr)) {
            ptr++;
        }
    }
    return ptr -line;
}

void printf_json_in_file(const char *output_file,const char *json_string){
    FILE *output = open_file(output_file,"w");
    if(output != NULL){
        fprintf(output,"%s\n",json_string);
        fclose(output);
    }
    else{
        printf("Failed to open file.\n");
    }
}

void printf_time_to_file(const char *file_name){
    FILE *file = open_file(file_name,"a");
    time_t now = time(NULL);
    struct tm *local = localtime(&now);
    fprintf(file, "TIME: %02d:%02d:%02d DATE:%02d-%02d-%04d\n",local->tm_hour, 
    local->tm_min, local->tm_sec, local->tm_mday, local->tm_mon + 1, local->tm_year + 1900);
    fclose(file);
}

void printf_time_to_file_custom(FILE *file) {
    time_t now = time(NULL);
    struct tm *local = localtime(&now);

    if (local != NULL) {
        fprintf(file, "TIME: %02d:%02d:%02d DATE:%02d-%02d-%04d\n",
                local->tm_hour, local->tm_min, local->tm_sec,
                local->tm_mday, local->tm_mon + 1, local->tm_year + 1900);
    } else {
        fprintf(file, "TIME: UNKNOWN DATE: UNKNOWN\n");
    }
}



void clear_file_to_run(const char *filename) {
    FILE *check_file = fopen(filename, "w");
    if (check_file == NULL) {
        perror("Unable to open file");
        return;
    }
    fclose(check_file);
}




