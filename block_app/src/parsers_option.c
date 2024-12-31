#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include "log.h"
#include "file_process.h"
#include "parsers_data.h"
#include "block_ip.h"


int scan_option = 0;
int option;
int option_index = 0;
int log_level_set = 0;

void print_help(){
    printf("Options:\n");
    printf("  -d, --debug <val>     Set log level (0=Disabled, 1=Error, 2=Warn, 3=Debug)\n");
    printf("  -h, --help            Print message information\n");
    printf("  -r, --remove          Remove rules in iptales and ipset\n");
    LOG(LOG_LVL_ERROR, "test7: %s, %s, %d\n", __FILE__, __func__, __LINE__);
}


void parsers_option(int argc, char *argv[])
{   
    while (1)
    {
        static struct option long_options[] =
            {
                {"help", no_argument, 0, 'h'},
                {"debug", required_argument, 0, 'd'},
                {"remove", no_argument, 0, 'r'},
                {0, 0, 0, 0}};
        option = getopt_long(argc, argv, "hd:r",long_options, &option_index);
        if (option == -1)
            break;
        switch (option)
        {
        case 0:
            if (long_options[option_index].flag != 0)
                break;
            printf("option %s", long_options[option_index].name);
            if (optarg)
                printf(" with arg: %s", optarg);
            printf("\n");
            break;
        
        case 'd':
        {
            int log_level = atoi(optarg);
            log_set_level(log_level);
            break;
            
        }

        case 'r': 
        {
            printf("Removing ipset, iptables chain and iptables rules...\n");
            break;
        }
        case 'h':
            printf("Usage: %s [options] [target]...\n", argv[0]);
            print_help();
            break;

        case '?':
            break;

        default:
            fprintf(stderr, "Usage: %s [-d loglevel] [-h]\n", argv[0]);
        }
    }
    LOG(LOG_LVL_DEBUG, "%s, %d: test8\n", __func__, __LINE__);

    if (optind < argc)
    {
        printf("non-option ARGV-elements: ");
        while (optind < argc)
            printf("%s ", argv[optind++]);
        putchar('\n');
    }
    LOG(LOG_LVL_ERROR, "test3: %s, %s, %d\n", __FILE__, __func__, __LINE__);
    LOG(LOG_LVL_WARN, "test4: %s, %s, %d\n", __FILE__, __func__, __LINE__);
    LOG(LOG_LVL_DEBUG, "test5: %s, %s, %d\n", __FILE__, __func__, __LINE__);
}
