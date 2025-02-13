#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include "log.h"
#include "file_process.h"
#include "parsers_data.h"
#include "block_ip.h"

int option;
int option_index = 0;

void print_help()
{
    PRINTF("Options:\n");
    PRINTF("  -d, --debug <val>     Set log level (0=Disabled, 1=Error, 2=Warn, 3=Debug)\n");
    PRINTF("  -h, --help            Print message information\n");
}

void PO_parsers_option(int argc, char *argv[])
{
    while (1)
    {
        int log_level;
        static struct option long_options[] =
            {
                {"help", no_argument, 0, 'h'},
                {"debug", required_argument, 0, 'd'},
                {0, 0, 0, 0}};
        
        option = getopt_long(argc, argv, "hd:", long_options, &option_index);
        if (option == -1)
            break;

        switch (option)
        {
        case 'd':
        {
            char *endptr;
            log_level = strtol(optarg, &endptr, 10);

            if (*endptr != '\0' || log_level < 0 || log_level > 3)
            {
                fprintf(stderr, "Error: Invalid log level value '%s'\n", optarg);
                print_help();
                exit(EXIT_FAILURE);
            }

            LOG_set_level(log_level);
            break;
        }

        case 'h':
            PRINTF("Usage: %s [options] [target]...\n", argv[0]);
            print_help();
            exit(EXIT_SUCCESS);

        case '?':
            fprintf(stderr, "Error: Invalid option or missing value.\n");
            print_help();
            exit(EXIT_FAILURE);

        default:
            fprintf(stderr, "Usage: %s [-d loglevel] [-h]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (optind < argc)
    {
        PRINTF("non-option ARGV-elements: ");
        while (optind < argc)
            PRINTF("%s ", argv[optind++]);
        fprintf(stderr, "\n");
        print_help();
        exit(EXIT_FAILURE);
    }
}




// #include <ctype.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <unistd.h>
// #include <getopt.h>
// #include <string.h>
// #include "log.h"
// #include "file_process.h"
// #include "parsers_data.h"
// #include "block_ip.h"
// #include "defines.h"


// int scan_option = 0;
// int option;
// int option_index = 0;
// int log_level_set = 0;

// typedef struct
// {
//     char key[MAX_KEY_LENGTH];
//     char value[MAX_VALUE_LENGTH];
// } ConfigItem;

// ConfigItem config_items[MAX_CONFIG_KEYS];
// int config_count = 0;

// void print_help()
// {
//     PRINTF("Options:\n");
//     PRINTF("  -d, --debug <val>     Set log level (0=Disabled, 1=Error, 2=Warn, 3=Debug)\n");
//     PRINTF("  -h, --help            Print message information\n");
//     PRINTF("  -c, --config <file>   Specify a configuration file\n");
// }

// void add_config_item(const char *key, const char *value)
// {
//     if (config_count >= MAX_CONFIG_KEYS)
//     {
//         fprintf(stderr, "Quá nhiều tham số trong file cấu hình\n");
//         return;
//     }
//     snprintf(config_items[config_count].key, MAX_KEY_LENGTH, "%s", key);
//     snprintf(config_items[config_count].value, MAX_VALUE_LENGTH, "%s", value);
//     config_count++;
// }

// const char *get_config_value(const char *key)
// {
//     for (int i = 0; i < config_count; i++)
//     {
//         if (strcmp(config_items[i].key, key) == 0)
//         {
//             return config_items[i].value;
//         }
//     }
//     return NULL;
// }

// void load_config(const char *config_file)
// {   
//     FILE *file;
//     char line[512], key[MAX_KEY_LENGTH], value[MAX_VALUE_LENGTH];
    
//     file = fopen(config_file, "r");
    
//     if (!file)
//     {
//         fprintf(stderr, "Không thể mở file cấu hình: %s\n", config_file);
//         exit(EXIT_FAILURE);
//     }

    
//     while (fgets(line, sizeof(line), file))
//     {
//         if (line[0] == '#' || line[0] == '\n')
//             continue;

        
//         if (sscanf(line, "%127[^=]=%255[^\n]", key, value) == 2)
//         {
//             add_config_item(key, value);
//         }
//     }

//     fclose(file);
// }

// void PO_parsers_option(int argc, char *argv[])
// {
//     const char *config_file = DEFAULT_CONFIG_FILE;

//     while (1)
//     {
//         int log_level;
//         static struct option long_options[] =
//             {
//                 {"help", no_argument, 0, 'h'},
//                 {"debug", required_argument, 0, 'd'},
//                 {"config", required_argument, 0, 'c'},
//                 {0, 0, 0, 0}};
//         option = getopt_long(argc, argv, "hd:c:", long_options, &option_index);
//         if (option == -1)
//             break;

//         switch (option)
//         {
//         case 0:
//             if (long_options[option_index].flag != 0)
//                 break;
//             PRINTF("option %s", long_options[option_index].name);
//             if (optarg)
//                 PRINTF(" with arg: %s", optarg);
//             PRINTF("\n");
//             break;

//         case 'd':
//             log_level = atoi(optarg);
//             LOG_set_level(log_level);
//             break;

//         case 'c':
//             config_file = optarg;
//             break;

//         case 'h':
//             PRINTF("Usage: %s [options] [target]...\n", argv[0]);
//             print_help();
//             exit(EXIT_SUCCESS);
//             break;

//         case '?':
//             break;

//         default:
//             fprintf(stderr, "Usage: %s [-d loglevel] [-c config_file] [-h]\n", argv[0]);
//             exit(EXIT_FAILURE);
//         }
//     }

//     load_config(config_file);
//     PRINTF("Loaded configuration from: %s\n", config_file);

//     for (int i = 0; i < config_count; i++)
//     {
//         PRINTF("%s = %s\n", config_items[i].key, config_items[i].value);
//     }
// }
