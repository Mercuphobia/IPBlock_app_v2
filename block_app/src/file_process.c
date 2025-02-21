#define _POSIX_C_SOURCE 2
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include "log.h"
#include "defines.h"

// char DEFAULT_CONFIG_FILE[MAX_PATH_LENGTH] = "/home/test/etc/config/app_config.txt";

char DEFAULT_CONFIG_FILE[MAX_PATH_LENGTH] = "/etc/config/app_config.txt";

char SRC_WEB_BLOCK_PATH[MAX_PATH_LENGTH] = "../../webserver/config/url_data.txt";
char DOMAIN_NAME_TXT_PATH[MAX_PATH_LENGTH] = "../../block_app/data/domain_name.txt";
char BLOCK_WEB_TXT_PATH[MAX_PATH_LENGTH] = "../../block_app/data/block_web.txt";
char LOG_FILE_PATH[MAX_PATH_LENGTH] = "../../block_app/data/log.txt";
char IP_DB_DIR[MAX_PATH_LENGTH] = "../../block_app/ip_db";
char DOMAIN_DIR[MAX_PATH_LENGTH] = "../../block_app/domain";

/* Describe: Retrieve the value of a given key from a configuration file.
 *
 * Parameters:
 *   key: The name of the configuration key to look up.
 *   value: A buffer to store the retrieved value.
 *   value_size: The maximum size of the value buffer.
 *
 * Return:
 *   If the function executes successfully, it retrieves the value associated with the given key
 *   and stores it in the provided buffer.  
 *   If the key is not found, the function returns -1.  
 *   If the configuration file cannot be opened, the function prints an error message and exits the program.  
 */
int get_config_value(const char *key, char *value, size_t value_size) {
    FILE *file;
    char line[256], *start, *delimiter, *key_end, *value_start, *value_end;

    file = fopen(DEFAULT_CONFIG_FILE, "r");
    if (!file) {
        perror("Failed to open config file");
        LOG(LOG_LVL_WARN, "%s, %d. Failed to open config file. Run with default config", __func__, __LINE__);
        //exit(EXIT_FAILURE);
        return -1;
    }
    while (fgets(line, sizeof(line), file)) {
        start = line;
        while (isspace((unsigned char)*start)) start++;

        if (*start == '#' || *start == '\0') continue;

        delimiter = strchr(start, '=');
        if (!delimiter) continue;

        key_end = delimiter - 1;

        while (key_end > start && isspace((unsigned char)*key_end)) key_end--;
        key_end[1] = '\0';

        if (strncmp(start, key, strlen(key)) == 0 && strlen(start) == strlen(key)) {
            value_start = delimiter + 1;

            while (isspace((unsigned char)*value_start)) value_start++;

            value_end = value_start + strlen(value_start) - 1;

            while (value_end > value_start && isspace((unsigned char)*value_end)) value_end--;

            value_end[1] = '\0';
            strncpy(value, value_start, value_size - 1);
            value[value_size - 1] = '\0';
            fclose(file);
            return 0;
        }
    }
    fclose(file);
    return -1;
}

void FP_init_path()
{   
    LOG(LOG_LVL_DEBUG, "%s, %d. Start", __func__, __LINE__);
    char temp_value[MAX_PATH_LENGTH];

    if (get_config_value("DEFAULT_CONFIG_FILE", temp_value, sizeof(temp_value)) == 0) {
        snprintf(DEFAULT_CONFIG_FILE, sizeof(DEFAULT_CONFIG_FILE), "%s", temp_value);
    }

    if (get_config_value("LOG_FILE_PATH", temp_value, sizeof(temp_value)) == 0) {
        snprintf(LOG_FILE_PATH, sizeof(LOG_FILE_PATH), "%s", temp_value);
    }

    if (get_config_value("DOMAIN_NAME_TXT_PATH", temp_value, sizeof(temp_value)) == 0) {
        snprintf(DOMAIN_NAME_TXT_PATH, sizeof(DOMAIN_NAME_TXT_PATH), "%s", temp_value);
    }

    if (get_config_value("BLOCK_WEB_TXT_PATH", temp_value, sizeof(temp_value)) == 0) {
        snprintf(BLOCK_WEB_TXT_PATH, sizeof(BLOCK_WEB_TXT_PATH), "%s", temp_value);
    }

    if (get_config_value("IP_DB_DIR", temp_value, sizeof(temp_value)) == 0) {
        snprintf(IP_DB_DIR, sizeof(IP_DB_DIR), "%s", temp_value);
    }

    if (get_config_value("DOMAIN_DIR", temp_value, sizeof(temp_value)) == 0) {
        snprintf(DOMAIN_DIR, sizeof(DOMAIN_DIR), "%s", temp_value);
    }

    LOG(LOG_LVL_DEBUG, "%s, %d. End", __func__, __LINE__);
}

FILE *open_file(const char *file_name, const char *mode)
{   
    FILE *file = fopen(file_name,mode);
    if(!file){
        perror("Open file false");
    }   
    return file;
    
}

void FP_create_empty_file(const char *filename) 
{
    LOG(LOG_LVL_DEBUG, "%s, %d Start, file name: %s", __func__, __LINE__, filename);

    FILE *check_file = fopen(filename, "w");
    if (check_file == NULL) 
    {
        LOG(LOG_LVL_ERROR, "%s, %d, End. Unable to open file. %s", __func__, __LINE__, filename);
        exit(EXIT_FAILURE);
    }
    fclose(check_file);

    LOG(LOG_LVL_DEBUG, "%s, %d, End ", __func__, __LINE__);
}

void FP_copy_file(const char *input_file, const char *output_file) 
{
    LOG(LOG_LVL_DEBUG, "%s, %d, Start ", __func__, __LINE__);

    FILE *fp1, *fp2;
    char buffer[128], command1[256], command2[256];
    
    snprintf(command1, sizeof(command1), "cat %s", input_file);
    fp1 = popen(command1, "r");
    if (fp1 == NULL) 
    {
        LOG(LOG_LVL_ERROR, "%s, %d, End, failed to run input %s", __func__, __LINE__, input_file);
        exit(EXIT_FAILURE);
    }

    snprintf(command2, sizeof(command2), "cat > %s", output_file);
    fp2 = popen(command2, "w");
    if (fp2 == NULL) 
    {
        pclose(fp1);
        LOG(LOG_LVL_ERROR, "%s, %d, End, failed to run output %s", __func__, __LINE__, output_file);
        exit(EXIT_FAILURE);
    }

    while (fgets(buffer, sizeof(buffer), fp1) != NULL) 
    {
        fputs(buffer, fp2);
    }

    pclose(fp1);
    pclose(fp2);
    LOG(LOG_LVL_DEBUG, "%s, %d, End ", __func__, __LINE__);
}




