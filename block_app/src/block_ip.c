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
#include "defines.h"

// run board//
#define IPSET_LIST_NO_STDOUT "/userfs/bin/ipset list %s > /dev/null 2>&1"
#define IPSET_CREATE "/userfs/bin/ipset create %s hash:ip"
#define IPSET_ADD "/userfs/bin/ipset add %s %s"
#define IPSET_DELETE_RULE "/userfs/bin/ipset destroy %s_%ld > /dev/null 2>&1"
#define IPSET_TEST_RULE "/userfs/bin/ipset test %s %s > /dev/null 2>&1"
#define IPSET_CREATE_NET "/userfs/bin/ipset create %s hash:net timeout 10000"
#define IPSET_DELETE_RULE_NET "/userfs/bin/ipset destroy %s > /dev/null 2>&1"

// // run vmware//
// #define IPSET_LIST_NO_STDOUT "ipset list %s > /dev/null 2>&1"
// #define IPSET_CREATE "ipset create %s hash:ip"
// #define IPSET_ADD "ipset add %s %s"
// #define IPSET_DELETE_RULE "ipset destroy %s_%ld > /dev/null 2>&1"
// #define IPSET_TEST_RULE "ipset test %s %s > /dev/null 2>&1"
// #define IPSET_CREATE_NET "ipset create %s hash:net timeout 10000"
// #define IPSET_DELETE_RULE_NET "ipset destroy %s > /dev/null 2>&1"

#define RULE_CREATE_CHAIN "iptables -N BLOCK_IP_CHAIN"
#define CHECK_NAME_CHAIN "iptables -L BLOCK_IP_CHAIN >/dev/null 2>&1"
#define CHECK_BLOCK_IP_CHAIN_INPUT "iptables -L INPUT | grep -q BLOCK_IP_CHAIN"
#define CHECK_BLOCK_IP_CHAIN_OUTPUT "iptables -L OUTPUT | grep -q BLOCK_IP_CHAIN"
#define CHECK_BLOCK_IP_CHAIN_FORWARD "iptables -L FORWARD | grep -q BLOCK_IP_CHAIN"
#define IP_TABLES_ADD_CHAIN_INPUT "iptables -A INPUT -j BLOCK_IP_CHAIN"
#define IP_TABLES_ADD_CHAIN_OUTPUT "iptables -A OUTPUT -j BLOCK_IP_CHAIN"
#define IP_TABLES_ADD_CHAIN_FORWARD "iptables -A FORWARD -j BLOCK_IP_CHAIN"

#define IP_TABLES_CHECK_RULES_IN_CHAIN "iptables -S BLOCK_IP_CHAIN | grep -q -- '-m set --match-set %s src -j DROP' > /dev/null 2>&1"
#define IP_TABLES_ADD_RULES_IN_CHAIN "iptables -A BLOCK_IP_CHAIN -m set --match-set %s src -j DROP > /dev/null 2>&1"
#define IP_TABLES_DELETE_RULES_IN_CHAIN "iptables -D BLOCK_IP_CHAIN -m set --match-set %s src -j DROP > /dev/null 2>&1"

#define RULE_CREATE_CHAIN_HAVE_MAC "iptables -N BLOCK_IP_CHAIN_HAVE_MAC"
#define CHECK_NAME_CHAIN_HAVE_MAC "iptables -L BLOCK_IP_CHAIN_HAVE_MAC >/dev/null 2>&1"
#define CHECK_BLOCK_IP_CHAIN_HAVE_MAC_INPUT "iptables -L INPUT | grep -q BLOCK_IP_CHAIN_HAVE_MAC"
#define CHECK_BLOCK_IP_CHAIN_HAVE_MAC_FORWARD "iptables -L FORWARD | grep -q BLOCK_IP_CHAIN_HAVE_MAC"
#define IP_TABLES_ADD_CHAIN_HAVE_MAC_INPUT "iptables -A INPUT -j BLOCK_IP_CHAIN_HAVE_MAC"
#define IP_TABLES_ADD_CHAIN_HAVE_MAC_FORWARD "iptables -A FORWARD -j BLOCK_IP_CHAIN_HAVE_MAC"

#define IP_TABLES_CHECK_RULES_IN_CHAIN_HAVE_MAC "iptables -S BLOCK_IP_CHAIN_HAVE_MAC | grep -q -- '-m mac --mac-source %s -m set --match-set %s dst -j DROP' > /dev/null 2>&1"
#define IP_TABLES_ADD_RULES_IN_CHAIN_HAVE_MAC "iptables -A BLOCK_IP_CHAIN_HAVE_MAC -m mac --mac-source %s -m set --match-set %s dst -j DROP > /dev/null 2>&1"
#define IP_TABLES_DELETE_RULES_IN_CHAIN_HAVE_MAC "iptables -D BLOCK_IP_CHAIN_HAVE_MAC -m mac --mac-source %s -m set --match-set %s dst -j DROP > /dev/null 2>&1"

int num_struct = 0;
char command[256], sub_command[256];

/* Description: Converts a given day of the week into its corresponding numeric value.
 *
 * Parameters:
 * - day: String representing the day of the week
 *
 * Return:
 * - Returns an integer corresponding to the day of the week:
 *   - Monday -> 0
 *   - Tuesday -> 1
 *   - Wednesday -> 2
 *   - Thursday -> 3
 *   - Friday -> 4
 *   - Saturday -> 5
 *   - Sunday -> 6
 * - Returns -1 if the input day is invalid.
 */
int BI_get_day_number(const char *day)
{
    LOG(LOG_LVL_DEBUG, "%s, %d: Start", __func__, __LINE__);
    if (strcmp(day, "Monday") == 0)
    {
        LOG(LOG_LVL_DEBUG, "%s, %d: End. day = %s", __func__, __LINE__, day);
        return 0;
    }

    if (strcmp(day, "Tuesday") == 0)
    {
        LOG(LOG_LVL_DEBUG, "%s, %d: End. day = %s", __func__, __LINE__, day);
        return 1;
    }

    if (strcmp(day, "Wednesday") == 0)
    {
        LOG(LOG_LVL_DEBUG, "%s, %d: End. day = %s", __func__, __LINE__, day);
        return 2;
    }

    if (strcmp(day, "Thursday") == 0)
    {
        LOG(LOG_LVL_DEBUG, "%s, %d: End. day = %s", __func__, __LINE__, day);
        return 3;
    }

    if (strcmp(day, "Friday") == 0)
    {
        LOG(LOG_LVL_DEBUG, "%s, %d: End. day = %s", __func__, __LINE__, day);
        return 4;
    }

    if (strcmp(day, "Saturday") == 0)
    {
        LOG(LOG_LVL_DEBUG, "%s, %d: End. day = %s", __func__, __LINE__, day);
        return 5;
    }

    if (strcmp(day, "Sunday") == 0)
    {
        LOG(LOG_LVL_DEBUG, "%s, %d: End. day = %s", __func__, __LINE__, day);
        return 6;
    }
    LOG(LOG_LVL_WARN, "%s, %d: End. day invalid = %s", __func__, __LINE__, day);

    return -1;
}

/* Describes: This function calculates the total number of seconds that have passed since
 * the beginning of the current week until the present moment. The steps include:
 *                  Retrieve the current time.
 *                  Convert the time to a structured format (year, month, day, etc.).
 *                  Determine the current day number in the week (Monday = 0, ..., Sunday = 6).
 *                  Convert the current day, hour, minute, and second into total seconds.
 *
 * Parameter:
 *      None.
 *
 * Output:
 *      Returns the total number of seconds from the start of the week to the current moment.
 */
long get_current_time_in_seconds()
{
    // LOG(LOG_LVL_DEBUG, "%s, %d: Start", __func__, __LINE__);
    time_t now;
    long total_seconds;
    struct tm *tm_now;
    int day_number;

    now = time(NULL);
    tm_now = localtime(&now);
    day_number = tm_now->tm_wday - 1;
    if (day_number < 0)
        day_number = 6;
    total_seconds = day_number * 86400 + tm_now->tm_hour * 3600 + tm_now->tm_min * 60 + tm_now->tm_sec;
    // LOG(LOG_LVL_DEBUG, "%s, %d: End total_seconds = %ld", __func__, __LINE__, total_seconds);
    return total_seconds;
}

/* Describes: This function checks if a specific ipset exists in the system by running a command to list ipsets.
 *
 * Parameter:
 *      - ipset_name: The name of the ipset to check for existence.
 *
 * Output:
 *      1: if the ipset exists.
 *      0: if the ipset does not exist.
 */
int check_ipset_exists(const char *ipset_name)
{
    LOG(LOG_LVL_DEBUG, "%s, %d: Start", __func__, __LINE__);

    int result;

    snprintf(command, sizeof(command), IPSET_LIST_NO_STDOUT, ipset_name);
    result = system(command);

    LOG(LOG_LVL_DEBUG, "%s, %d: End", __func__, __LINE__);

    return result == 0;
}

/* Description: This function adds an ipset to a specified iptables chain if the rule does not already exist.
 *
 * Parameters:
 * - ipset_name: The name of the ipset to be added.
 *
 * Output:
 * Adds the ipset to the BLOCK_IP_CHAIN ​​in iptables if the rule does not already exist.
 */
void add_ipset_to_chain(const char *ipset_name)
{
    LOG(LOG_LVL_DEBUG, "%s, %d: Start", __func__, __LINE__);

    snprintf(command, sizeof(command), IP_TABLES_CHECK_RULES_IN_CHAIN, ipset_name);
    if (system(command) != 0)
    {
        snprintf(sub_command, sizeof(sub_command), IP_TABLES_ADD_RULES_IN_CHAIN, ipset_name);
        int result_sub_command = system(sub_command);
        if (result_sub_command != 0)
        {
            PRINTF("Can't add rules %s in chain\n", ipset_name);
            LOG(LOG_LVL_WARN, "%s, %d: Can't add rules in chain", __func__, __LINE__);
        }
        else
        {
            LOG(LOG_LVL_DEBUG, "%s, %d Added ipset %s to BLOCK_IP_CHAIN with DROP action.", __func__, __LINE__, ipset_name);
            PRINTF("Added ipset %s to BLOCK_IP_CHAIN with DROP action.\n", ipset_name);
        }
    }
    LOG(LOG_LVL_DEBUG, "%s, %d: End", __func__, __LINE__);
}

/* Describes: This function deletes an ipset from a chain in iptables
 *
 * Parameters:
 * - ipset_name: The name of the ipset to be removed.
 *
 * Output:
 * Removes the ipset from a chain in iptables
 */
void delete_ipset_to_chain(const char *ipset_name)
{
    LOG(LOG_LVL_DEBUG, "%s, %d: Start", __func__, __LINE__);

    snprintf(command, sizeof(command), IP_TABLES_CHECK_RULES_IN_CHAIN, ipset_name);
    if (system(command) == 0)
    {
        snprintf(command, sizeof(command), IP_TABLES_DELETE_RULES_IN_CHAIN, ipset_name);
        system(command);
        PRINTF("Removed ipset %s from BLOCK_IP_CHAIN with DROP action.\n", ipset_name);
        LOG(LOG_LVL_DEBUG, "%s, %d Removed ipset %s from BLOCK_IP_CHAIN with DROP action.", __func__, __LINE__, ipset_name);
    }
    LOG(LOG_LVL_DEBUG, "%s, %d: End", __func__, __LINE__);
}

/* Describes: This function adds an ipset related to a MAC address to a specific iptables chain if the rule does not already exist.
 *
 * Parameter:
 *      - ipset_name: The name of the ipset to be added.
 *      - mac: The MAC address associated with the ipset.
 *
 * Output:
 *      Adds the ipset with the MAC address to the BLOCK_IP_CHAIN_HAVE_MAC in iptables if the rule doesn't already exist.
 */
void add_ipset_have_mac_to_chain(const char *ipset_name, const char *mac)
{
    LOG(LOG_LVL_DEBUG, "%s, %d: Start", __func__, __LINE__);

    snprintf(command, sizeof(command), IP_TABLES_CHECK_RULES_IN_CHAIN_HAVE_MAC, mac, ipset_name);
    if (system(command) != 0)
    {
        snprintf(command, sizeof(command), IP_TABLES_ADD_RULES_IN_CHAIN_HAVE_MAC, mac, ipset_name);
        system(command);
        PRINTF("Added ipset %s with MAC %s to BLOCK_IP_CHAIN_HAVE_MAC with DROP action.\n", ipset_name, mac);
        LOG(LOG_LVL_DEBUG, "%s, %d Added ipset %s with MAC %s to BLOCK_IP_CHAIN_HAVE_MAC with DROP action.", __func__, __LINE__, ipset_name, mac);
    }
    LOG(LOG_LVL_DEBUG, "%s, %d: End", __func__, __LINE__);
}

/* Describes: This function deletes an ipset from a chain in iptables that is associated with a specific MAC address.
 *
 * Parameter:
 *      - ipset_name: The name of the ipset to be removed.
 *      - mac: The MAC address associated with the ipset to be removed.
 *
 * Output:
 *      Removes the ipset associated with the MAC address from the iptables chain and logs the operation.
 */
void delete_ipset_have_mac_to_chain(const char *ipset_name, const char *mac)
{
    LOG(LOG_LVL_DEBUG, "%s, %d: Start", __func__, __LINE__);

    snprintf(command, sizeof(command), IP_TABLES_CHECK_RULES_IN_CHAIN_HAVE_MAC, mac, ipset_name);
    if (system(command) == 0)
    {

        snprintf(command, sizeof(command), IP_TABLES_DELETE_RULES_IN_CHAIN_HAVE_MAC, mac, ipset_name);
        system(command);
        PRINTF("Removed ipset %s with MAC %s to BLOCK_IP_CHAIN_HAVE_MAC with DROP action.\n", ipset_name, mac);
        LOG(LOG_LVL_DEBUG, "%s, %d Removed ipset %s with MAC %s to BLOCK_IP_CHAIN_HAVE_MAC with DROP action.", __func__, __LINE__, ipset_name, mac);
    }

    LOG(LOG_LVL_DEBUG, "%s, %d: End", __func__, __LINE__);
}

/* Describes: This function is designed to create and add chains for blocking IP and MAC addresses.
 * The steps include:
 *                  Check if the BLOCK_IP_CHAIN exists, if not, create it.
 *                  Add BLOCK_IP_CHAIN to INPUT, OUTPUT, and FORWARD chains in iptables.
 *                  Check if the BLOCK_IP_CHAIN_HAVE_MAC exists, if not, create it.
 *                  Add BLOCK_IP_CHAIN_HAVE_MAC to INPUT and FORWARD chains in iptables.
 *
 * Parameter:
 *
 * Output:
 * BLOCK_IP_CHAIN is created and added to INPUT, OUTPUT, and FORWARD chains.
 * BLOCK_IP_CHAIN_HAVE_MAC is created and added to INPUT and FORWARD chains.
 */
void create_and_add_chain()
{
    LOG(LOG_LVL_DEBUG, "%s, %d: Start", __func__, __LINE__);

    int retry = 0;

    while (system(CHECK_NAME_CHAIN) != 0)
    {
        if (system(RULE_CREATE_CHAIN) == 0)
        {
            LOG(LOG_LVL_DEBUG, "%s, %d: Create BLOCK_IP_CHAIN success.", __func__, __LINE__);
            break;
        }

        retry++;
        LOG(LOG_LVL_WARN, "%s, %d. Failed to create BLOCK_IP_CHAIN. Attempt %d", __func__, __LINE__, retry);
        PRINTF("Failed to create BLOCK_IP_CHAIN. Attempt %d\n", retry);

        if (retry >= 3)
        {
            LOG(LOG_LVL_ERROR, "%s, %d. End. Exceeded max retries. Create BLOCK_IP_CHAIN false.", __func__, __LINE__);
            PRINTF("Exceeded max retries. Create BLOCK_IP_CHAIN false.\n");
            exit(EXIT_FAILURE);
        }
        sleep(1);
    }

    retry = 0;
    while (system(CHECK_BLOCK_IP_CHAIN_INPUT) != 0)
    {
        if (system(IP_TABLES_ADD_CHAIN_INPUT) == 0)
        {
            LOG(LOG_LVL_DEBUG, "%s, %d: Create INPUT BLOCK_IP_CHAIN success.", __func__, __LINE__);
            PRINTF("Added BLOCK_IP_CHAIN to INPUT chain.\n");
            break;
        }

        retry++;
        LOG(LOG_LVL_WARN, "%s, %d. Failed to create INPUT BLOCK_IP_CHAIN. Attempt %d", __func__, __LINE__, retry);
        PRINTF("Failed to create INTPUT BLOCK_IP_CHAIN. Attempt %d\n", retry);

        if (retry >= 3)
        {
            LOG(LOG_LVL_ERROR, "%s, %d. End. Exceeded max retries. Create INPUT BLOCK_IP_CHAIN false.", __func__, __LINE__);
            PRINTF("Exceeded max retries. Create INPUT BLOCK_IP_CHAIN false.\n");
            exit(EXIT_FAILURE);
        }
        sleep(1);
    }

    retry = 0;
    while (system(CHECK_BLOCK_IP_CHAIN_OUTPUT) != 0)
    {
        if (system(IP_TABLES_ADD_CHAIN_OUTPUT) == 0)
        {
            LOG(LOG_LVL_DEBUG, "%s, %d: Create OUTPUT BLOCK_IP_CHAIN success.", __func__, __LINE__);
            PRINTF("Added BLOCK_IP_CHAIN to OUTPUT chain.\n");
            break;
        }

        retry++;
        LOG(LOG_LVL_WARN, "%s, %d. Failed to create OUTPUT BLOCK_IP_CHAIN. Attempt %d", __func__, __LINE__, retry);
        PRINTF("Failed to create OUTPUT BLOCK_IP_CHAIN. Attempt %d\n", retry);

        if (retry >= 3)
        {
            LOG(LOG_LVL_ERROR, "%s, %d. End. Exceeded max retries. Create OUTPUT BLOCK_IP_CHAIN false.", __func__, __LINE__);
            PRINTF("Exceeded max retries. Create OUTPUT BLOCK_IP_CHAIN false.\n");
            exit(EXIT_FAILURE);
        }
        sleep(1);
    }


    retry = 0;
    while (system(CHECK_BLOCK_IP_CHAIN_FORWARD) != 0)
    {
        if (system(IP_TABLES_ADD_CHAIN_FORWARD) == 0)
        {
            LOG(LOG_LVL_DEBUG, "%s, %d: Create FORWARD BLOCK_IP_CHAIN success.", __func__, __LINE__);
            PRINTF("Added BLOCK_IP_CHAIN to FORWARD chain.\n");
            break;
        }

        retry++;
        LOG(LOG_LVL_WARN, "%s, %d. Failed to create FORWARD BLOCK_IP_CHAIN. Attempt %d", __func__, __LINE__, retry);
        PRINTF("Failed to create FORWARD BLOCK_IP_CHAIN. Attempt %d\n", retry);

        if (retry >= 3)
        {
            LOG(LOG_LVL_ERROR, "%s, %d. End. Exceeded max retries. Create FORWARD BLOCK_IP_CHAIN false.", __func__, __LINE__);
            PRINTF("Exceeded max retries. Create FORWARD BLOCK_IP_CHAIN false.\n");
            exit(EXIT_FAILURE);
        }
        sleep(1);
    }


    retry = 0;
    while (system(CHECK_NAME_CHAIN_HAVE_MAC) != 0)
    {
        if (system(RULE_CREATE_CHAIN_HAVE_MAC) == 0)
        {
            LOG(LOG_LVL_DEBUG, "%s, %d: Create BLOCK_IP_CHAIN_HAVE_MAC success.", __func__, __LINE__);
            break;
        }

        retry++;
        LOG(LOG_LVL_WARN, "%s, %d. Failed to create BLOCK_IP_CHAIN_HAVE_MAC. Attempt %d", __func__, __LINE__, retry);
        PRINTF("Failed to create BLOCK_IP_CHAIN_HAVE_MAC. Attempt %d\n", retry);

        if (retry >= 3)
        {
            LOG(LOG_LVL_ERROR, "%s, %d. End. Exceeded max retries. Create BLOCK_IP_CHAIN_HAVE_MAC false.", __func__, __LINE__);
            PRINTF("Exceeded max retries. Create BLOCK_IP_CHAIN_HAVE_MAC false.\n");
            exit(EXIT_FAILURE);
        }
        sleep(1);
    }

    retry = 0;
    while (system(CHECK_BLOCK_IP_CHAIN_HAVE_MAC_INPUT) != 0)
    {
        if (system(IP_TABLES_ADD_CHAIN_HAVE_MAC_INPUT) == 0)
        {
            LOG(LOG_LVL_DEBUG, "%s, %d: Create INPUT BLOCK_IP_CHAIN_HAVE_MAC.", __func__, __LINE__);
            PRINTF("Added BLOCK_IP_CHAIN_HAVE_MAC to INPUT chain.\n");
            break;
        }
        
        retry++;
        LOG(LOG_LVL_WARN, "%s, %d. Failed to create INPUT BLOCK_IP_CHAIN_HAVE_MAC. Attempt %d", __func__, __LINE__, retry);
        PRINTF("Failed to create INPUT BLOCK_IP_CHAIN_HAVE_MAC. Attempt %d\n", retry);

        if (retry >= 3)
        {
            LOG(LOG_LVL_ERROR, "%s, %d. End. Exceeded max retries. Create INPUT BLOCK_IP_CHAIN_HAVE_MAC false.", __func__, __LINE__);
            PRINTF("Exceeded max retries. Create INPUT BLOCK_IP_CHAIN_HAVE_MAC false.\n");
            exit(EXIT_FAILURE);
        }
        sleep(1);
    }

    retry = 0;
    while (system(CHECK_BLOCK_IP_CHAIN_HAVE_MAC_FORWARD) != 0)
    {
        if (system(IP_TABLES_ADD_CHAIN_HAVE_MAC_FORWARD) == 0)
        {
            LOG(LOG_LVL_DEBUG, "%s, %d: Create FORWARD BLOCK_IP_CHAIN_HAVE_MAC.", __func__, __LINE__);
            PRINTF("Added BLOCK_IP_CHAIN_HAVE_MAC to FORWARD chain.\n");
            break;
        }

        retry++;
        LOG(LOG_LVL_WARN, "%s, %d. Failed to create FORWARD BLOCK_IP_CHAIN_HAVE_MAC. Attempt %d", __func__, __LINE__, retry);
        PRINTF("Failed to create FORWARD BLOCK_IP_CHAIN_HAVE_MAC. Attempt %d\n", retry);

        if (retry >= 3)
        {
            LOG(LOG_LVL_ERROR, "%s, %d. End. Exceeded max retries. Create FORWARD BLOCK_IP_CHAIN_HAVE_MAC false.", __func__, __LINE__);
            PRINTF("Exceeded max retries. Create FORWARD BLOCK_IP_CHAIN_HAVE_MAC false.\n");
            exit(EXIT_FAILURE);
        }
        sleep(1);
    }

    LOG(LOG_LVL_DEBUG, "%s, %d: End", __func__, __LINE__);
}

/* Describes: Searches for a file in a directory. When it finds a file that matches the name
 *            it is looking for, it stores the full path of the file in the variable found_path
 *
 * Parameter:
 *      directory_path - The path of the directory to search in.
 *      filename - The name of the file to search for.
 *      found_path - A buffer to store the full path of the found file.
 *
 * Output:
 *      1: If file is found and saved in Found_path
 *      0: If not found.
 */
int find_file_in_directory(const char *directory_path, const char *filename, char *found_path)
{
    // LOG(LOG_LVL_DEBUG, "%s, %d: Start", __func__, __LINE__);

    DIR *directory;
    struct dirent *directory_entry;
    char full_path[MAX_PATH_LENGTH];
    struct stat file_info;

    directory = opendir(directory_path);
    if (directory == NULL)
    {
        LOG(LOG_LVL_WARN, "%s, %d. End. Unable to open directory in directory: %s", __func__, __LINE__, directory);
        return 0;
    }

    while ((directory_entry = readdir(directory)) != NULL)
    {
        if (strcmp(directory_entry->d_name, ".") == 0 || strcmp(directory_entry->d_name, "..") == 0)
        {
            continue;
        }
        snprintf(full_path, sizeof(full_path), "%s/%s", directory_path, directory_entry->d_name);

        if (stat(full_path, &file_info) == 0)
        {
            if (S_ISDIR(file_info.st_mode))
            {
                if (find_file_in_directory(full_path, filename, found_path))
                {
                    closedir(directory);
                    return 1;
                }
            }
            else if (S_ISREG(file_info.st_mode))
            {
                if (strcmp(directory_entry->d_name, filename) == 0)
                {
                    snprintf(found_path, MAX_PATH_LENGTH, "%s", full_path);
                    closedir(directory);
                    return 1;
                }
            }
        }
    }
    closedir(directory);

    // LOG(LOG_LVL_DEBUG, "%s, %d: End", __func__, __LINE__);
    return 0;
}

/* Describes: This function checks whether a given file is empty by determining its size.
 *
 * Parameter:
 *      - file_path: The path to the file that needs to be checked.
 *
 * Return:
 *      1: if the file is empty
 *      0: if it is not empty
 *     -1: if the file cannot be opened
 */
int is_empty_file(const char *file_path)
{
    LOG(LOG_LVL_DEBUG, "%s, %d: Start", __func__, __LINE__);

    long file_size;
    FILE *file;

    file = fopen(file_path, "r");
    if (file == NULL)
    {
        perror("Failed to open file");
        LOG(LOG_LVL_WARN, "%s, %d: Failed to open file.", __func__, __LINE__);
        return -1;
    }
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fclose(file);

    LOG(LOG_LVL_DEBUG, "%s, %d: End", __func__, __LINE__);

    return (file_size == 0);
}

/* Describes: This function creates a new ipset from a file if the ipset does not already exist.
 *
 * Parameter:
 *      - filename: The name of the ipset to be created.
 *
 * Output:
 *      Creates a new ipset if it does not already exist and logs the operation.
 */
void create_ipset_in_file(char *filename)
{
    // LOG(LOG_LVL_DEBUG, "%s, %d: Start", __func__, __LINE__);

    if (!check_ipset_exists(filename))
    {
        snprintf(command, sizeof(command), IPSET_CREATE_NET, filename);
        system(command);
    }

    // LOG(LOG_LVL_DEBUG, "%s, %d: End", __func__, __LINE__);
}

void run_command(const char *command)
{
    int command_result = system(command);
    if (command_result != 0)
    {
        fprintf(stderr, "Command failed: %s\n", command);
        LOG(LOG_LVL_ERROR, "Command failed: %s, %s, %s, %d\n", command, __FILE__, __func__, __LINE__);
    }
}

/* Describes: This function reads a list of IP addresses from a file and adds them to an ipset
 *            if they do not already exist.
 *
 * Parameters:
 *      - filepath: The path to the file containing the list of IP addresses.
 *      - filename: The name of the ipset where the IPs will be added.
 *
 * Output:
 *      Reads each IP from the file, checks if it exists in the ipset, and adds it if not present.
 */
void add_list_ip_from_file(char *filepath, char *ipset_name)
{
    LOG(LOG_LVL_DEBUG, "%s, %d: Start", __func__, __LINE__);

    FILE *file;
    char ip[MAX_IP_LENGTH];

    file = fopen(filepath, "r");
    if (file == NULL)
    {
        perror("Unable to open file");
        LOG(LOG_LVL_WARN, "%s, %d: End. Unable to open file in: %s", __func__, __LINE__, filepath);
        return;
    }

    while (fgets(ip, sizeof(ip), file))
    {
        ip[strcspn(ip, "\n")] = '\0';
        ip[strcspn(ip, "\r")] = '\0';
        snprintf(command, sizeof(command), IPSET_TEST_RULE, ipset_name, ip);
        int command_result = system(command);
        if (command_result != 0)
        {
            snprintf(command, sizeof(command), IPSET_ADD, ipset_name, ip);
            run_command(command);
        }
    }
    fclose(file);

    LOG(LOG_LVL_DEBUG, "%s, %d. End", __func__, __LINE__);
}

/* Describes: This function checks if an ipset exists, and if it does, deletes it
 *            from the chain along with its associated MAC address.
 *
 * Parameters:
 *          - url: The URL used to generate the ipset name.
 *          - mac: The MAC address associated with the ipset.
 *          - start_block_time: The timestamp used to create a unique ipset name.
 *
 * Output:
 *          - If the ipset exists, removes it from the chain using a system command.
 *          - Delete the ipset associated with the specified MAC address.
 */
void check_and_delete_ipset_have_mac_to_chain(char *url, char *mac, long start_block_time)
{
    LOG(LOG_LVL_DEBUG, "%s, %d. Start", __func__, __LINE__);

    char ipset_name[256];
    snprintf(ipset_name, sizeof(ipset_name), "%s_%ld", url, start_block_time);
    if (check_ipset_exists(ipset_name))
    {
        snprintf(command, sizeof(command), IPSET_DELETE_RULE, url, start_block_time);
        system(command);
        delete_ipset_have_mac_to_chain(ipset_name, mac);
    }

    LOG(LOG_LVL_DEBUG, "%s, %d. End", __func__, __LINE__);
}

/* Describes: This function checks and removes an ipset associated with a URL
 *            and not containing a MAC address from the block chain if it exists.
 *
 * Parameters:
 *          - url: The URL used to generate the ipset name.
 *          - start_block_time: The timestamp used to create a unique ipset name.
 *
 * Output:
 *          - If ipset exists, it will be removed from the blocking chain.
 */
void check_and_delete_ipset_to_chain(char *url, long start_block_time)
{
    LOG(LOG_LVL_DEBUG, "%s, %d. Start", __func__, __LINE__);

    char ipset_name[256];
    snprintf(ipset_name, sizeof(ipset_name), "%s_%ld", url, start_block_time);
    if (check_ipset_exists(ipset_name))
    {
        snprintf(command, sizeof(command), IPSET_DELETE_RULE, url, start_block_time);
        system(command);
        delete_ipset_to_chain(ipset_name);
    }

    LOG(LOG_LVL_DEBUG, "%s, %d. End", __func__, __LINE__);
}

/* Describes: This function creates an ipset, associates it with a MAC address,
 *            and adds IP addresses to the ipset from a specified file or an existing domain file.
 *
 * Parameters:
 *      - filepath: The path to the file containing the list of IP addresses.
 *      - url: The URL used to generate the ipset name.
 *      - mac: The MAC address associated with the ipset.
 *      - start_block_time: The timestamp used to create a unique ipset name.
 *
 * Output:
 *      - Creates a new ipset with a name based on the URL and timestamp.
 *      - Links the ipset to the specified MAC address.
 *      - Searches for an existing file in the domain directory.
 *      - Adds IP addresses to the ipset from the found file or the provided file.
 */
void find_file_create_chain_and_add_ipset_have_mac(char *filepath, char *url, char *mac, long start_block_time)
{
    LOG(LOG_LVL_DEBUG, "%s, %d. Start", __func__, __LINE__);

    char ipset_name[256], file_in_domain_folder[MAX_PATH_LENGTH];

    snprintf(ipset_name, sizeof(ipset_name), "%s_%ld", url, start_block_time);
    create_ipset_in_file(ipset_name);
    add_ipset_have_mac_to_chain(ipset_name, mac);

    if (find_file_in_directory(DOMAIN_DIR, url, file_in_domain_folder))
    {
        if (!is_empty_file(file_in_domain_folder))
        {
            add_list_ip_from_file(file_in_domain_folder, ipset_name);
        }
        else
        {
            add_list_ip_from_file(filepath, ipset_name);
        }
    }
    else
    {
        add_list_ip_from_file(filepath, ipset_name);
    }

    LOG(LOG_LVL_DEBUG, "%s, %d. End", __func__, __LINE__);
}

/* Describes: This function creates an ipset, and adds IP addresses to the ipset
 *            from a specified file or an existing domain file.
 *
 * Parameters:
 *      - filepath: The path to the file containing the list of IP addresses.
 *      - url: The URL used to generate the ipset name.
 *      - start_block_time: The timestamp used to create a unique ipset name.
 *
 * Output:
 *      - Creates a new ipset with a name based on the URL and timestamp.
 *      - Searches for an existing file in the domain directory.
 *      - Adds IP addresses to the ipset from the found file or the provided file.
 */
void find_file_create_chain_and_add_ipset(char *filepath, char *url, long start_block_time)
{
    LOG(LOG_LVL_DEBUG, "%s, %d. Start", __func__, __LINE__);

    char ipset_name[256], file_in_domain_folder[MAX_PATH_LENGTH];

    snprintf(ipset_name, sizeof(ipset_name), "%s_%ld", url, start_block_time);
    create_ipset_in_file(ipset_name);
    add_ipset_to_chain(ipset_name);

    if (find_file_in_directory(DOMAIN_DIR, url, file_in_domain_folder))
    {
        if (!is_empty_file(file_in_domain_folder))
        {
            add_list_ip_from_file(file_in_domain_folder, ipset_name);
        }
        else
        {
            add_list_ip_from_file(filepath, ipset_name);
        }
    }
    else
    {
        add_list_ip_from_file(filepath, ipset_name);
    }

    LOG(LOG_LVL_DEBUG, "%s, %d. End", __func__, __LINE__);
}

/* Description: Processes a list of domain information and manages IP sets based on time-based access rules.
 *              If the current time is within the blocking period, it creates and adds IP sets.
 *              Otherwise, it removes the IP sets from the chain.
 *
 * Parameters:
 * - filename: String representing the name of the domain file.
 * - filepath: String representing the full path to the domain file.
 *
 * Output:
 * - Updates IP sets by adding or removing entries based on the blocking time rules.
 */
void create_and_add_ipset_ip_db(char *filename, char *filepath)
{
    LOG(LOG_LVL_DEBUG, "%s, %d. Start", __func__, __LINE__);

    domain_info *list;
    time_t current_time;
    long current_local_time, start_block_time, end_block_time;
    char ipset_name[256], file_in_domain_folder[MAX_PATH_LENGTH];
    char *url, *mac;

    list = PD_get_list_domain_info(DOMAIN_NAME_TXT_PATH, &num_struct);
    for (int i = 0; i < num_struct; i++)
    {
        current_time = time(NULL);
        current_local_time = get_current_time_in_seconds();
        start_block_time = list[i].start_time_block;
        end_block_time = list[i].end_time_block;
        url = list[i].url;
        mac = list[i].mac;

        if (strlen(list[i].mac) == 17)
        {
            if (start_block_time < end_block_time)
            {
                if (current_local_time < start_block_time || current_local_time > end_block_time)
                {
                    if (strcmp(filename, list[i].url) == 0)
                    {
                        check_and_delete_ipset_have_mac_to_chain(url, mac, start_block_time);
                    }
                }
                else if (current_local_time >= start_block_time && current_local_time < end_block_time)
                {
                    if (strcmp(filename, list[i].url) == 0)
                    {

                        find_file_create_chain_and_add_ipset_have_mac(filepath, url, mac, start_block_time);
                    }
                }
            }
            else if (start_block_time == end_block_time)
            {
                if (current_local_time == start_block_time && current_local_time == end_block_time)
                {
                    if (strcmp(filename, list[i].url) == 0)
                    {
                        check_and_delete_ipset_have_mac_to_chain(url, mac, start_block_time);
                    }
                }
            }
            else
            {
                if (current_local_time < start_block_time && current_local_time > end_block_time)
                {
                    if (strcmp(filename, list[i].url) == 0)
                    {
                        check_and_delete_ipset_have_mac_to_chain(url, mac, start_block_time);
                    }
                }
                else if (current_local_time >= start_block_time && current_local_time > end_block_time)
                {
                    if (strcmp(filename, list[i].url) == 0)
                    {
                        find_file_create_chain_and_add_ipset_have_mac(filepath, url, mac, start_block_time);
                    }
                }
                else if (current_local_time < start_block_time && current_local_time <= end_block_time)
                {
                    if (strcmp(filename, list[i].url) == 0)
                    {
                        find_file_create_chain_and_add_ipset_have_mac(filepath, url, mac, start_block_time);
                    }
                }
            }
        }
        else
        {
            if (start_block_time < end_block_time)
            {
                if (current_local_time < start_block_time || current_local_time > end_block_time)
                {
                    if (strcmp(filename, list[i].url) == 0)
                    {
                        check_and_delete_ipset_to_chain(url, start_block_time);
                    }
                }
                else if (current_local_time >= start_block_time && current_local_time < end_block_time)
                {
                    if (strcmp(filename, list[i].url) == 0)
                    {
                        find_file_create_chain_and_add_ipset(filepath, url, start_block_time);
                    }
                }
            }
            else if (start_block_time == end_block_time)
            {
                if (current_local_time == start_block_time && current_local_time == end_block_time)
                {
                    if (strcmp(filename, list[i].url) == 0)
                    {
                        check_and_delete_ipset_to_chain(url, start_block_time);
                    }
                }
            }
            else
            {
                if (current_local_time < start_block_time && current_local_time > end_block_time)
                {
                    if (strcmp(filename, list[i].url) == 0)
                    {
                        check_and_delete_ipset_to_chain(url, start_block_time);
                    }
                }
                else if (current_local_time >= start_block_time && current_local_time > end_block_time)
                {
                    if (strcmp(filename, list[i].url) == 0)
                    {
                        find_file_create_chain_and_add_ipset(filepath, url, start_block_time);
                    }
                }
                else if (current_local_time < start_block_time && current_local_time <= end_block_time)
                {
                    if (strcmp(filename, list[i].url) == 0)
                    {
                        find_file_create_chain_and_add_ipset(filepath, url, start_block_time);
                    }
                }
            }
        }
    }
    LOG(LOG_LVL_DEBUG, "%s, %d. End", __func__, __LINE__);
}

void BI_run_block_ip()
{
    LOG(LOG_LVL_DEBUG, "%s, %d. Start", __func__, __LINE__);

    int num_web = 0;
    create_and_add_chain();
    domain_info *list = PD_get_list_domain_info(DOMAIN_NAME_TXT_PATH, &num_web);
    for (int i = 0; i < num_web; i++)
    {
        char file_path[MAX_PATH_LENGTH];
        if (find_file_in_directory(IP_DB_DIR, list[i].url, file_path))
        {
            create_and_add_ipset_ip_db(list[i].url, file_path);
        }
    }

    LOG(LOG_LVL_DEBUG, "%s, %d. End", __func__, __LINE__);
}

// int cleanup_chain(const char *chain_name) {
//     char command[256];
//     snprintf(command, sizeof(command), "iptables -L %s >/dev/null 2>&1", chain_name);
//     if (system(command) != 0) {
//         return 0;
//     }
//     snprintf(command, sizeof(command), "iptables -F %s", chain_name);
//     if (system(command) != 0) {
//         return -1;
//     }
//     snprintf(command, sizeof(command), "iptables -D INPUT -j %s", chain_name);
//     if (system(command) != 0) {
//     }
//     snprintf(command, sizeof(command), "iptables -D OUTPUT -j %s", chain_name);
//     if (system(command) != 0) {
//     }
// 	snprintf(command, sizeof(command), "iptables -D FORWARD -j %s", chain_name);
//     if (system(command) != 0) {
//     }
//     snprintf(command, sizeof(command), "iptables -X %s", chain_name);
//     if (system(command) != 0) {
//         return -1;
//     }
//     return 0;
// }

// int cleanup_chain_have_mac(const char *chain_name) {
//     char command[256];
//     snprintf(command, sizeof(command), "iptables -L %s >/dev/null 2>&1", chain_name);
//     if (system(command) != 0) {
//         return 0;
//     }
//     snprintf(command, sizeof(command), "iptables -F %s", chain_name);
//     if (system(command) != 0) {
//         return -1;
//     }
//     snprintf(command, sizeof(command), "iptables -D INPUT -j %s", chain_name);
//     if (system(command) != 0) {
//     }
// 	snprintf(command, sizeof(command), "iptables -D FORWARD -j %s", chain_name);
//     if (system(command) != 0) {
//     }
//     snprintf(command, sizeof(command), "iptables -X %s", chain_name);
//     if (system(command) != 0) {
//         return -1;
//     }
//     return 0;
// }