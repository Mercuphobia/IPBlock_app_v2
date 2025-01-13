#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "parsers_option.h"
#include "file_process.h"
#include "get_data.h"
#include "parsers_data.h"
#include "log.h"
#include "block_ip.h"
#include <unistd.h>
#include <sys/wait.h>
#include <pthread.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include "dns.h"
#include "packet_process.h"


// Review: move to config file or header file of module accordingly
// use full path. For ex. /tmp/.., /etc/..
#define SRC_WEB_BLOCK_PATH "../../webserver/config/url_data.txt"
#define DES_WEB_BLOCK_PATH "../../block_app/data/block_web.txt"
#define BLOCK_WEB "../../block_app/data/block_web.txt"
#define IP_FILE "../../block_app/data/ip.txt"
#define CHECK_FILE "../../block_app/data/check.txt"
#define DATA_FILE "../../block_app/data/data.txt"
#define DOMAIN_NAME_TXT_PATH "../../block_app/data/domain_name.txt"
#define DOMAIN_DIR "../../block_app/domain" 
#define DELETE_INTERVAL 100

// Review: change global name: gDnsThreadId,...
pthread_t thread1, thread2, thread3;
volatile sig_atomic_t sigint_received = 0;

static void* app1(void* arg)
{
    //signal(SIGINT,cleanup);
    clear_file_to_run(DOMAIN_NAME_TXT_PATH);

    // Review: how about false??

    // Review: ????
    transfer_data(SRC_WEB_BLOCK_PATH, DES_WEB_BLOCK_PATH);
    // cp src dst
    
    // 
    printf_domain_name_to_file(DOMAIN_NAME_TXT_PATH);
    
    // Review: unused logs
    LOG(LOG_LVL_ERROR, "testmain1: %s, %s, %d\n", __FILE__, __func__, __LINE__);
    start_packet_capture();
}

void* app2(void* arg) {
    while (1) {
        clear_file_to_run(IP_FILE);
        clear_file_to_run(CHECK_FILE);
        run_block_ip();
        sleep(4);
    }
}


pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

void* app3(void* arg) {
    time_t last_delete_time = time(NULL);

    while (1) {
        time_t current_time = time(NULL);
        if (difftime(current_time, last_delete_time) >= DELETE_INTERVAL) {
            DIR *dir = opendir(DOMAIN_DIR);
            if (dir == NULL) {
                perror("Cannot open folder");
                sleep(1);
                continue;
            }
            struct dirent *entry;
            char file_path[1024];
            while ((entry = readdir(dir)) != NULL) {
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                    continue;
                }
                snprintf(file_path, sizeof(file_path), "%s/%s", DOMAIN_DIR, entry->d_name);
                pthread_mutex_lock(&file_mutex);
                FILE *file = fopen(file_path, "w");
                if (file == NULL) {
                    perror("Cannot open file to delete content");
                } else {
                    fclose(file);
                }
                pthread_mutex_unlock(&file_mutex);
            }

            closedir(dir);
            last_delete_time = current_time; 
        }
        sleep(1);
    }
    return NULL;
}


// Review: Remove unused code
void sigint_handler(int sig)
{
    sigint_received = 1;
    cleanup();
    sleep(2);
    //delete_iptable_rules_chain_and_ipset();
    exit(0);
}

//glocal

// Review: add more debug log to know status code.

int main(int argc, char *argv[])
{
    // Review: check failed case
    parsers_option(argc, argv);

    // Review: Remove log
    LOG(LOG_LVL_ERROR, "testmain1: %s, %s, %d\n", __FILE__, __func__, __LINE__);

    // data cond 
    printf_domain_name_to_file();
    
    // Review: IPtables rule cleanup always
    //signal(SIGINT, sigint_handler);

    // Review: Modify app name into useful. For ex, app1 --> dns_packet_handle_thread
    pthread_create(&thread1, NULL, app1, NULL);
    pthread_create(&thread2, NULL, app2, NULL);
    pthread_create(&thread3, NULL, app3, NULL);
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    pthread_join(thread3, NULL);
    return 0;
}