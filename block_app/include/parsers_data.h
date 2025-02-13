#include <stdbool.h>
#ifndef PARSERS_DATA_H
#define PARSERS_DATA_H

#define MAX_LENGTH 256
#define MAX_TIME_LENGTH 20

typedef struct
{
    char url[MAX_LENGTH];
    char mac[MAX_LENGTH];
    char start_day[MAX_LENGTH];
    char start_time[MAX_LENGTH];
    char end_day[MAX_LENGTH];
    char end_time[MAX_LENGTH];
} website_block;

typedef struct
{
    char url[MAX_LENGTH];
    char mac[MAX_LENGTH];
    long start_time_block;
    long end_time_block;
} domain_info;

/* Describes: Function reads the target from a file, parses the data in the file, and stores it into a website_block 
 *            struct array.
 *
 * Parameter:
 *   filename: This file contains a list of websites to block, each line in the file has the format:
 *                  url, mac, start_day, start_time, end_day, end_time
 *   line_count: Is a pointer to an integer variable that stores the number of lines (or website_block structures) read 
 *               from the file. The value of this variable is updated after the file is read.
 *
 * Return:
 *         Pointer to a dynamic array of website_block structures containing data read from the file.
 *         If an error occurs (file opening failed, insufficient memory), the function returns NULL.
 */
website_block *PD_get_list_block_web(const char *filename, int *line_count);

/* Describes: Function reads a list of domain information from a file, then stores this data in an array of 
 *            domain_info structures.
 *
 * Parameter:
 *   filename: This file contains a list of websites to block, each line in the file has the format:
 *                  url, mac, start_day, start_time, end_day, end_time
 *   list_domain: Is a pointer to an integer variable that stores the number of lines (or domain_info structures) read 
 *               from the file. The value of this variable is updated after the file is read.
 *
 * Return:
 *         Pointer to a dynamic array of domain_info structures containing data read from the file.
 *         If an error occurs (file opening failed, insufficient memory), the function returns NULL.
 */
domain_info *PD_get_list_domain_info(const char *filename, int *list_domain);

/* Describes: Function used to check whether a line of text exists in an opened file.
 *
 * Parameter:
 *   file: A FILE pointer points to a previously opened file (usually using fopen).
 *         The file must be opened in read mode.
 *   line: The character string to check if it exists in the file.
 *
 * Return:
 *        true: If the line string is found in the file.
 *        false: If not found.
 */
bool PD_is_line_in_file(FILE *file, const char *line);

/* Describes: Function is used to extract and write domain information from a website_block list 
 *            to a file (if the domain does not already exist in the file). Here is a detailed explanation 
 *            and suggested renaming of the function.
 *
 * Parameter:
 *   file: The name of the file where the domain information will be written. 
 *         The file is opened in write mode and if the file already exists, the content will be appended to the end.
 * Output:
 *        
 * 
 */
void PD_printf_domain_name_to_file(const char *filename);

#endif //PARSERS_DATA_H
