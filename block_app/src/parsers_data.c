#include <stdio.h>
#include <string.h>
#include "parsers_data.h"
#include "log.h"
#include <stdbool.h>
#include <block_ip.h>
#include "defines.h"

char line[256];

bool PD_is_line_in_file(FILE *file, const char *line)
{   
    LOG(LOG_LVL_DEBUG, "%s, %d. Start. ", __func__, __LINE__);

    char buffer[256];

    rewind(file);
    while (fgets(buffer, sizeof(buffer), file) != NULL)
    {
        if (strcmp(buffer, line) == 0)
        {   
            LOG(LOG_LVL_DEBUG, "%s, %d. End. ", __func__, __LINE__);
            return true;           
        }
    }

    LOG(LOG_LVL_DEBUG, "%s, %d. End. ", __func__, __LINE__);
    return false;
}

/* Describe: Convert a given day and time into the total number of seconds from the start of the week
 *
 * Parameters:
 *   - day: A string representing the day of the week (e.g., "Monday", "Tuesday").
 *   - time: A string representing the time in "HH:MM" format.
 *
 * Return:
 *      It returns the total number of seconds from the beginning of the week.
 *      -1 if the input day is invalid.
 */
long convert_to_seconds(const char *day, const char *time)
{   
    LOG(LOG_LVL_DEBUG, "%s, %d. Start. day: %s, time: %s", __func__, __LINE__, day, time);

    int day_number;
    int hours, minutes;
    long total_seconds;

    day_number = BI_get_day_number(day);
    if (day_number == -1)
    {
        PRINTF("Invalid day: %s\n", day);
        LOG(LOG_LVL_WARN, "%s, %d. End. Invalid day: %s  ", __func__, __LINE__, day);
        return -1;
    }
    
    sscanf(time, "%d:%d", &hours, &minutes);
    total_seconds = day_number * 86400 + hours * 3600 + minutes * 60;

    LOG(LOG_LVL_DEBUG, "%s, %d. End. total_seconds: %ld", __func__, __LINE__, total_seconds);
    return total_seconds;
}

website_block *PD_get_list_block_web(const char *filename, int *line_count)
{   
    LOG(LOG_LVL_DEBUG, "%s, %d. Start ", __func__, __LINE__);
    
    website_block *list_block_web = NULL;
    *line_count = 0;
    int number_struct = INIT_NUMBER_STRUCT;
    FILE *file;
    char *token;

    list_block_web = malloc(number_struct * sizeof(website_block));
    if (list_block_web == NULL)
    {
        LOG(LOG_LVL_ERROR, "%s, %d. End. Unable to allocate memory ", __func__, __LINE__);
        exit(EXIT_FAILURE);
    }
    file = fopen(filename, "r");
    if (file == NULL)
    {
        LOG(LOG_LVL_ERROR, "%s, %d. End. Unable to open file %s ", __func__, __LINE__, filename);
        free(list_block_web);
        exit(EXIT_FAILURE);
    }
    while (fgets(line, sizeof(line), file))
    {
        if (*line_count >= number_struct)
        {
            number_struct *= 2;
            list_block_web = realloc(list_block_web, number_struct * sizeof(website_block));
            if (list_block_web == NULL)
            {
                LOG(LOG_LVL_ERROR, "%s, %d. End. Unable to allocate memory ", __func__, __LINE__);
                fclose(file);
                exit(EXIT_FAILURE);
            }
        }
        line[strcspn(line, "\n")] = '\0';

        token = strtok(line, ", ");
        if (token != NULL)
        {
            strncpy(list_block_web[*line_count].url, token, MAX_LENGTH);
        }
        token = strtok(NULL, ", ");
        if(token != NULL)
        {
            strncpy(list_block_web[*line_count].mac, token, MAX_LENGTH);
        }
        else 
        {
            list_block_web[*line_count].url[0] = '\0';
        }
        token = strtok(NULL, " ");
        if (token != NULL)
        {
            strncpy(list_block_web[*line_count].start_day, token, MAX_LENGTH);
        }
        else
        {
            list_block_web[*line_count].start_day[0] = '\0';
        }
        token = strtok(NULL, ", ");
        if (token != NULL)
        {
            strncpy(list_block_web[*line_count].start_time, token, MAX_LENGTH);
        }
        else
        {
            list_block_web[*line_count].start_time[0] = '\0';
        }
        token = strtok(NULL, " ");
        if (token != NULL)
        {
            strncpy(list_block_web[*line_count].end_day, token, MAX_LENGTH);
        }
        else
        {
            list_block_web[*line_count].end_day[0] = '\0';
        }
        token = strtok(NULL, " ");
        if (token != NULL)
        {
            strncpy(list_block_web[*line_count].end_time, token, MAX_LENGTH);
        }
        else
        {
            list_block_web[*line_count].end_time[0] = '\0';
        }
        (*line_count)++;
    }
    fclose(file);

    LOG(LOG_LVL_DEBUG, "%s, %d. End. number of block_web = %d ", __func__, __LINE__, *line_count);

    return list_block_web;
}

domain_info *PD_get_list_domain_info(const char *filename, int *list_domain)
{   
    LOG(LOG_LVL_DEBUG, "%s, %d. Start. ", __func__, __LINE__);

    domain_info *list = NULL;
    *list_domain = 0;
    int number_struct = INIT_NUMBER_STRUCT;
    FILE *file;
    char line[MAX_LENGTH];

    list = malloc(number_struct * sizeof(domain_info));
    if (list == NULL)
    {
        LOG(LOG_LVL_WARN, "%s, %d. End. Unable to allocate memory ", __func__, __LINE__);
        return NULL;
    }

    file = fopen(filename, "r");
    if (file == NULL)
    {
        LOG(LOG_LVL_WARN, "%s, %d. End. Unable to open file ", __func__, __LINE__);
        free(list);
        return NULL;
    }

    while (fgets(line, sizeof(line), file))
    {
        if (*list_domain >= number_struct)
        {
            number_struct *= 2;
            list = realloc(list, number_struct * sizeof(domain_info));
            if (list == NULL)
            {
                //perror("Unable to allocate memory");
                LOG(LOG_LVL_WARN, "%s, %d. End. Unable to allocate memory ", __func__, __LINE__);
                fclose(file);
                return NULL;
            }
        }
        line[strcspn(line, "\n")] = '\0';
        sscanf(line, "%[^,], %[^,], %ld, %ld",
               list[*list_domain].url,
               list[*list_domain].mac,
               &list[*list_domain].start_time_block,
               &list[*list_domain].end_time_block);

        (*list_domain)++;
    }

    fclose(file);
    LOG(LOG_LVL_DEBUG, "%s, %d. End. number list_domain_info: %d ", __func__, __LINE__, *list_domain);

    return list;
}

/* Describe: Extract the main domain name from a given URL.
 *
 * Parameters:
 *   url: A string containing the input URL.
 *   domain: A string buffer to store the extracted domain name.
 *
 * Output:
 *   - If the function executes successfully, it extracts the main domain name and stores it in `domain`.
 *   - If the URL contains "www.", it is removed.
 *   - The domain name is taken as the substring before the first '.'.
 */
void extract_domain(const char* url, char* domain) {
    LOG(LOG_LVL_DEBUG, "%s, %d. Start ", __func__, __LINE__);

    char *start, *dot;
    size_t len;

    start = strstr(url, "www.");
    if (start != NULL) {
        start += 4;
    } else {
        start = (char*)url;
    }

    dot = strchr(start, '.');
    if (dot != NULL) {
        len = dot - start;
        strncpy(domain, start, len);
        domain[len] = '\0';
    } else {
        strcpy(domain, start);
    }
    LOG(LOG_LVL_DEBUG, "%s, %d. End. url: %s -> domain: %s ", __func__, __LINE__, url, domain);
}

/* Description: Reads a list of blocked websites and writes domain information to a file if not already present.
 *              The information includes the domain name, MAC address, and blocking time range.
 *
 * Parameters:
 * - filename: String representing the name of the file to store the domain information.
 *
 * Output:
 * - Appends domain information to the specified file if the entry does not already exist.
 */
void PD_printf_domain_name_to_file(const char* filename) {
    LOG(LOG_LVL_DEBUG, "%s, %d. Start ", __func__, __LINE__);

    int result_count = 0;
    website_block *list_block;
    FILE *file;
    char url[256], mac[20], domain[256], line[256];
    long start_time_block, end_time_block;

    file = fopen(filename, "a+");
    if (file == NULL) {
        LOG(LOG_LVL_ERROR, "%s, %d. End. Unable to open file %s ", __func__, __LINE__, filename);
        exit(EXIT_FAILURE);
    }

    list_block = PD_get_list_block_web(BLOCK_WEB_TXT_PATH, &result_count);
    for (int i = 0; i < result_count; i++) {
        strcpy(url, list_block[i].url);
        strcpy(mac, list_block[i].mac);
        start_time_block = convert_to_seconds(list_block[i].start_day, list_block[i].start_time);
        end_time_block = convert_to_seconds(list_block[i].end_day, list_block[i].end_time);
        extract_domain(url, domain);
        snprintf(line, sizeof(line), "%s, %s, %ld, %ld\n", domain, mac, start_time_block, end_time_block);
        if (!PD_is_line_in_file(file, line)) 
        {
            fprintf(file, "%s", line);
        }
    }

    fclose(file);
    free(list_block);

    LOG(LOG_LVL_DEBUG, "%s, %d. End ", __func__, __LINE__);
}
