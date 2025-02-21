#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "parsers_option.h"
#include "file_process.h"
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
#include "defines.h"

pthread_t thread1, thread2;

void *resolve_ip(void *arg)
{
    LOG(LOG_LVL_DEBUG, "%s, %d: Start ", __func__, __LINE__);

    FP_create_empty_file(DOMAIN_NAME_TXT_PATH);
    FP_copy_file(SRC_WEB_BLOCK_PATH, BLOCK_WEB_TXT_PATH);
    PD_printf_domain_name_to_file(DOMAIN_NAME_TXT_PATH);
    PP_start_packet_capture();

    LOG(LOG_LVL_DEBUG, "%s, %d: End ", __func__, __LINE__);
}

void *block_ip(void *arg)
{
    LOG(LOG_LVL_DEBUG, "%s, %d: Start ", __func__, __LINE__);
    while (1)
    {
        BI_run_block_ip();
        sleep(SLEEP_TIME_TO_RUN);
    }
    
    LOG(LOG_LVL_DEBUG, "%s, %d: End ", __func__, __LINE__);
}

int main(int argc, char *argv[])
{   
    LOG(LOG_LVL_DEBUG, "%s, %d: Start ", __func__, __LINE__);
    FP_init_path();
    PO_parsers_option(argc, argv);
    pthread_create(&thread1, NULL, resolve_ip, NULL);
    pthread_create(&thread2, NULL, block_ip, NULL);
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    LOG(LOG_LVL_DEBUG, "%s, %d: End ", __func__, __LINE__);
    return 0;
}