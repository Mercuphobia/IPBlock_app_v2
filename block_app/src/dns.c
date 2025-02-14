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
#include "defines.h"


int DNS_get_dns_query_length(unsigned char *dns_query)
{   
    //LOG(LOG_LVL_DEBUG, "%s, %d: Start ", __func__, __LINE__);
    int name_length = 0;
    while (dns_query[name_length] != 0)
    {
        name_length += dns_query[name_length] + ONE_BYTE;
    }
    //LOG(LOG_LVL_DEBUG, "%s, %d. End. with query_length = %d ", __func__, __LINE__, name_length + ONE_BYTE + FOUR_BYTE);

    return name_length + ONE_BYTE + FOUR_BYTE;
}

void DNS_decode_dns_name_answer(unsigned char *dns_packet, unsigned char *buffer, int *offset, int start)
{   
    //LOG(LOG_LVL_DEBUG, "%s, %d: Start ", __func__, __LINE__);

    int i = start, j = 0, jumped = 0, jump_offset = 0, pointer_offset, len;

    while (dns_packet[i] != 0)
    {
        if ((dns_packet[i] & 0xC0) == 0xC0)
        {
            if (!jumped)
            {
                jump_offset = i + 2;
            }
            jumped = 1;
            pointer_offset = ((dns_packet[i] & 0x3F) << 8) | dns_packet[i + 1];
            i = pointer_offset;
        }
        else
        {
            len = dns_packet[i];
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

    //LOG(LOG_LVL_DEBUG, "%s, %d: End ", __func__, __LINE__);
}

unsigned char *get_dns_answer_name(unsigned char *dns_packet, int answer_offset)
{   
    //LOG(LOG_LVL_DEBUG, "%s, %d: Start ", __func__, __LINE__);

    unsigned char *decoded_name = malloc(256);
    int offset = 0;

    if (decoded_name == NULL)
    {
        PRINTF("Memory allocation failed\n");
        //LOG(LOG_LVL_WARN, "%s, %d: End. Memory allocation failed ", __func__, __LINE__);
        return NULL;
    }
    DNS_decode_dns_name_answer(dns_packet, decoded_name, &offset, answer_offset);

    //LOG(LOG_LVL_DEBUG, "%s, %d: End. decoded_name = %s ", __func__, __LINE__, decoded_name);
    return decoded_name;
}

/* Describe: Recursively search for a file in a directory and its subdirectories.  
 *  
 * Parameters:  
 *   - dir_path: A string representing the path of the directory to search in.  
 *   - filename: A string representing the name of the file to search for.  
 *   - found_path: A pointer to a character array where the full path of the found file will be stored.  
 *  
 * Return:  
 *   - 1: if the file is found, and its full path is stored in found_path.  
 *   - 0:  if the file is not found or if an error occurs while opening the directory.    
 */
int find_file_in_subfolders(const char *dir_path, const char *filename, char *found_path)
{   
    //LOG(LOG_LVL_DEBUG, "%s, %d: Start ", __func__, __LINE__);
    DIR *dir = opendir(dir_path);
    if (dir == NULL)
    {
        perror("Unable to open directory");
        LOG(LOG_LVL_ERROR, "end find_file_in_subfolders(). Unable to open directory %s, %s, %s, %s, %d\n",
                            dir_path, filename,  __FILE__, __func__, __LINE__);
        //LOG(LOG_LVL_WARN, "%s, %d: End. Unable to open directory %s  ", __func__, __LINE__, dir_path);
        return 0;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }
        char full_path[MAX_PATH_LENGTH];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        struct stat statbuf;
        if (stat(full_path, &statbuf) == 0)
        {
            if (S_ISDIR(statbuf.st_mode))
            {
                if (find_file_in_subfolders(full_path, filename, found_path))
                {
                    closedir(dir);
                    return 1;
                }
            }
            else if (S_ISREG(statbuf.st_mode))
            {
                if (strcmp(entry->d_name, filename) == 0)
                {
                    snprintf(found_path, MAX_PATH_LENGTH, "%s", full_path);
                    closedir(dir);
                    return 1;
                }
            }
        }
    }
    closedir(dir);
    //LOG(LOG_LVL_DEBUG, "%s, %d: End. ", __func__, __LINE__);
    return 0;
}

/* Description: Checks if a file exists in the given directory (including subdirectories). If not, creates the file.
*
* Parameters:
* - folder: String representing the directory path where the file should be checked or created.
* - website_name: String representing the name of the file to be checked or created.
* - is_domain: Integer flag specifying the storage location of the file:
* - If is_domain == 1, the file is stored directly inside the directory.
* - If is_domain == 0, the file is stored inside the "other" subdirectory within the directory.
*
* Output:
* create the file if it does not exist
*/
void create_file_if_not_exists(const char *folder, const char *website_name, int is_domain)
{   
    LOG(LOG_LVL_DEBUG, "%s, %d: Start website_name_path: %s", __func__, __LINE__, website_name);

    char result_path[512], filepath[512];
    FILE *file;

    if (!find_file_in_subfolders(folder, website_name, result_path))
    {
        if (is_domain)
        {
            snprintf(filepath, sizeof(filepath), "%s/%s", folder, website_name);
        }
        else
        {
            snprintf(filepath, sizeof(filepath), "%s/other/%s", folder, website_name);
        }

        file = fopen(filepath, "a+");
        if (file == NULL)
        {
            fprintf(stderr, "Unable to create file: %s\n", filepath);
            LOG(LOG_LVL_WARN, "%s, %d: End Unable to create file: %s", __func__, __LINE__, filepath);
            return;
        }
        fclose(file);
    }

    LOG(LOG_LVL_DEBUG, "%s, %d: End ", __func__, __LINE__);
}

/* Description: Writes an IP address to a file if it does not already exist in the file.  
 *  
 * Parameters:  
 * - website_name: String representing the website associated with the IP address.  
 * - file_path: String representing the path to the file where the IP should be stored.  
 * - ip_str: String representing the IP address to be written to the file.  
 *  
 * Output:  
 * - Writes the IP address to the file if it is not already present.  
 */
void write_ip_to_file(const char *website_name, const char *file_path, const char *ip_str)
{   
    LOG(LOG_LVL_DEBUG, "%s, %d: Start website_name: %s, ip: %s ", __func__, __LINE__, website_name, ip_str);

    char line[512];
    bool ip_found = false;
    FILE *file;

    file = fopen(file_path, "a+");
    if (file == NULL)
    {
        fprintf(stderr, "Unable to open file: %s\n", file_path);
        LOG(LOG_LVL_WARN, "%s, %d: End. . Unable to open file %s ", __func__, __LINE__, file_path);
        return;
    }
    fseek(file, 0, SEEK_SET);
    
    while (fgets(line, sizeof(line), file))
    {
        if (strstr(line, ip_str))
        {
            ip_found = true;
            break;
        }
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    
    if (!ip_found)
    {
        if (file_size > 0)
        {
            fprintf(file, "\n%s", ip_str);
        }
        else
        {
            fprintf(file, "%s", ip_str);
        }
    }

    fclose(file);
    LOG(LOG_LVL_DEBUG, "%s, %d: End ", __func__, __LINE__);
}

/* Description: Extracts the website name from the given domain or URL. 
 * The function will remove the "http://", "https://" and "www." prefixes, if present. 
 * The function will extract the first part of the domain name (before the first dot).
 *
 * Parameters:
 * - domain_name: A string representing the full domain name or URL.
 *
 * Returns:
 * Returns a pointer to the extracted website name.
 * If the input is invalid or the extraction fails, the function returns NULL.
 *
 */
char *get_website_name_from_domain_name(const char *domain_name)
{   
    LOG(LOG_LVL_DEBUG, "%s, %d: Start ", __func__, __LINE__);

    char buffer[256];
    char *token, *name = NULL;

    strncpy(buffer, domain_name, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    if (strncmp(buffer, "http://", 7) == 0)
    {
        token = strtok(buffer + 7, "/");
    }
    else if (strncmp(buffer, "https://", 8) == 0)
    {
        token = strtok(buffer + 8, "/");
    }
    else
    {
        token = strtok(buffer, "/");
    }
    if (token != NULL && strncmp(token, "www.", 4) == 0)
    {
        token += 4;
    }
    if (token != NULL)
    {
        char *dot = strchr(token, '.');
        if (dot != NULL)
        {
            *dot = '\0';
        }
        name = token;
    }

    LOG(LOG_LVL_DEBUG, "%s, %d: End. name = %s", __func__, __LINE__, name);
    return name;
}

/* Description: Processes a DNS answer, extracts the IP address, and saves it in a specified folder if the domain is in the block list.  
 *  
 * Parameters:  
 * - dns_answer: Pointer to the DNS answer section of the packet.  
 * - dns_payload_content: Pointer to the full DNS payload content.  
 * - folder: Pointer to the directory where the IP should be saved.  
 * - is_domain: Integer flag specifying the storage location:  
 *   - If is_domain == 1, the file is stored directly inside the directory.  
 *   - If is_domain == 0, the file is stored inside the "other" subdirectory within the directory.  
 *  
 * Output:  
 * - Extracts the IP address from the DNS answer and stores it in a file if the domain is in the block list.  
 */
void DNS_process_dns_answer_and_save_ip_in_folder(unsigned char *dns_answer, unsigned char *dns_payload_content, 
                                    unsigned char *folder, int is_domain)
{
    //LOG(LOG_LVL_DEBUG, "%s, %d: Start ", __func__, __LINE__);

    int answer_offset = 0, name_length = 0;
    unsigned short type, data_len;

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

    type = ntohs(*(unsigned short *)(dns_answer + name_length));
    data_len = ntohs(*(unsigned short *)(dns_answer + name_length + 8));

    if (type == 1 && data_len == 4)
    {
        struct in_addr ipv4_addr;
        char *domain_name, *ip_str, file_path_in_folder[512], *web_name;
        int num_struct = 0;
        website_block *list;

        memcpy(&ipv4_addr, dns_answer + name_length + 10, sizeof(ipv4_addr));
        domain_name = get_dns_answer_name(dns_payload_content, answer_offset);
        ip_str = inet_ntoa(ipv4_addr);

        list = PD_get_list_block_web(BLOCK_WEB_TXT_PATH, &num_struct);

        for (int i = 0; i < num_struct; i++)
        {
            if (strstr(domain_name, (char *)list[i].url) != NULL)
            {
                web_name = get_website_name_from_domain_name(list[i].url);
                create_file_if_not_exists(folder, web_name, is_domain);
                if (find_file_in_subfolders(folder, web_name, file_path_in_folder))
                {
                    write_ip_to_file(web_name, file_path_in_folder, ip_str);
                }
            }
        }
    }

    //LOG(LOG_LVL_DEBUG, "%s, %d: End ", __func__, __LINE__);
}