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
#include "dns.h"
#include "packet_process.h"


#define SRC_WEB_BLOCK_PATH "../../webserver/config/url_data.txt"
#define DES_WEB_BLOCK_PATH "../../block_app/data/block_web.txt"
#define BLOCK_WEB "../../block_app/data/block_web.txt"
#define IP_FILE "../../block_app/data/ip.txt"
#define CHECK_FILE "../../block_app/data/check.txt"
#define DATA_FILE "../../block_app/data/data.txt"
#define DOMAIN_NAME_TXT_PATH "../../block_app/data/domain_name.txt"



pthread_t thread1, thread2;
volatile sig_atomic_t sigint_received = 0;

void* app1(void* arg) {
    //signal(SIGINT,cleanup);
    clear_file_to_run(DOMAIN_NAME_TXT_PATH);
    transfer_data(SRC_WEB_BLOCK_PATH, DES_WEB_BLOCK_PATH);
    printf_domain_name_to_file(DOMAIN_NAME_TXT_PATH);
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

void sigint_handler(int sig) {
    sigint_received = 1;
    cleanup();
    sleep(2);
    //delete_iptable_rules_chain_and_ipset();
    exit(0);
}

int main(int argc, char *argv[]) {
    parsers_option(argc, argv);
    LOG(LOG_LVL_ERROR, "testmain1: %s, %s, %d\n", __FILE__, __func__, __LINE__);
    //signal(SIGINT, sigint_handler);
    pthread_create(&thread1, NULL, app1, NULL);
    pthread_create(&thread2, NULL, app2, NULL);
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    return 0;
}