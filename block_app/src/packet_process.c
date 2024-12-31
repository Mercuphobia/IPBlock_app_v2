#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <string.h>
#include "dns.h"
#include "file_process.h"
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <time.h>
#include "log.h"
#include "parsers_data.h"


#include "block_ip.h"

#define PORT_DNS 53

// #define RULE_DELETE_INPUT_SPORT "iptables -D INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0"
// #define RULE_DELETE_INPUT_DPORT "iptables -D INPUT -p udp --dport 53 -j NFQUEUE --queue-num 0"
// #define RULE_DELETE_OUTPUT_SPORT "iptables -D OUTPUT -p udp --sport 53 -j NFQUEUE --queue-num 0"
// #define RULE_DELETE_OUTPUT_DPORT "iptables -D OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0"

// #define RULE_INPUT_SPORT "iptables -I INPUT 1 -p udp --sport 53 -j NFQUEUE --queue-num 0"
// #define RULE_INPUT_DPORT "iptables -I INPUT 1 -p udp --dport 53 -j NFQUEUE --queue-num 0"
// #define RULE_OUTPUT_SPORT "iptables -I OUTPUT 1 -p udp --sport 53 -j NFQUEUE --queue-num 0"
// #define RULE_OUTPUT_DPORT "iptables -I OUTPUT 1 -p udp --dport 53 -j NFQUEUE --queue-num 0"


#define FILE_DATA "../../block_app/data/data.txt"
#define DOMAIN_PATH "../../block_app/domain"
#define DATABASE_PATH "../../block_app/ip_db"


#define RULE_CREATE_CHAIN "iptables -N RESOLVE_CHAIN"
#define RULE_DELETE_CHAIN "iptables -F RESOLVE_CHAIN && iptables -D INPUT -j RESOLVE_CHAIN && iptables -D OUTPUT -j RESOLVE_CHAIN && iptables -X RESOLVE_CHAIN"


#define RULE_ADD_TO_INPUT "iptables -I INPUT -j RESOLVE_CHAIN"
#define RULE_ADD_TO_OUTPUT "iptables -I OUTPUT -j RESOLVE_CHAIN"
#define RULE_ADD_TO_FORWARD "iptables -I FORWARD -j RESOLVE_CHAIN"

#define RULE_ADD_DNS_SPORT "iptables -A RESOLVE_CHAIN -p udp --sport 53 -j NFQUEUE --queue-num 0"
#define RULE_ADD_DNS_DPORT "iptables -A RESOLVE_CHAIN -p udp --dport 53 -j NFQUEUE --queue-num 0"

#define CHECK_NAME_CHAIN "iptables -L RESOLVE_CHAIN >/dev/null 2>&1"
#define CHECK_RESOLVE_CHAIN_INPUT "iptables -L INPUT | grep -q RESOLVE_CHAIN"
#define CHECK_RESOLVE_CHAIN_OUTPUT "iptables -L OUTPUT | grep -q RESOLVE_CHAIN"
#define CHECK_RESOLVE_CHAIN_FORWARD "iptables -L FORWARD | grep -q RESOLVE_CHAIN"
#define CHECK_RULE_DNS_SPORT "iptables -L RESOLVE_CHAIN | grep -q 'sport 53'"
#define CHECK_RULE_DNS_DPORT "iptables -L RESOLVE_CHAIN | grep -q 'dport 53'"


void cleanup()
{
    LOG(LOG_LVL_ERROR, "test_cleanup: %s, %s, %d\n", __FILE__, __func__, __LINE__);
    system(RULE_DELETE_CHAIN);
    exit(0);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    u_int32_t id;
    struct nfqnl_msg_packet_hdr *packet_header;
    packet_header = nfq_get_msg_packet_hdr(nfa);
    if (packet_header)
    {
        id = ntohl(packet_header->packet_id);
    }
    LOG(LOG_LVL_ERROR, "testmain1: %s, %s, %d\n", __FILE__, __func__, __LINE__);
    unsigned char *packet_data;
    int ret = nfq_get_payload(nfa, &packet_data);
    if (ret >= 0)
    {
        struct iphdr *ip_header = (struct iphdr *)packet_data;
        if (ip_header->protocol == IPPROTO_UDP)
        {
            struct udphdr *udp_header = (struct udphdr *)(packet_data + (ip_header->ihl * 4));

            struct in_addr src_ip = {ip_header->saddr};
            struct in_addr dest_ip = {ip_header->daddr};

            if (ntohs(udp_header->source) == PORT_DNS)
            {
                unsigned char *dns_size = (unsigned char *)(packet_data + (ip_header->ihl * 4) + sizeof(struct udphdr));
                struct dns_header *dns = (struct dns_header *)dns_size;
                if (ntohs(dns->qdcount) == 1 && ntohs(dns->ancount) > 0)
                {
                    unsigned char *dns_payload_content = (unsigned char *)(dns_size + sizeof(struct dns_header));
                    int dns_payload_size = ret - (sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header));

                    unsigned char *dns_query = dns_size + sizeof(struct dns_header);
                    int query_length = get_dns_query_length(dns_query);
                    unsigned char *dns_answer = dns_query + query_length;
                    int number_of_answer = ntohs(dns->ancount);

                    for(int i=0;i<number_of_answer;i++){
                        LOG(LOG_LVL_ERROR, "testmain1: %s, %s, %d\n", __FILE__, __func__, __LINE__);
                        //printf_dns_answer_to_file(dns_answer, dns_payload_content,FILE_DATA);
                        //printf_dns_answer_to_folder_and_file(dns_answer, dns_payload_content,DOMAIN_PATH);
                        printf_ip_to_db(dns_answer, dns_payload_content, DATABASE_PATH);
                        int name_length = 0;
                        if ((dns_answer[0] & 0xC0) == 0xC0) {
                            name_length = 2;
                        } else {
                            while (dns_answer[name_length] != 0) {
                                name_length += dns_answer[name_length] + 1;
                            }
                            name_length += 1;
                        }
                        unsigned short data_len = ntohs(*(unsigned short *)(dns_answer + name_length + 8));
                        dns_answer += name_length + 10 + data_len;
                    }
                    LOG(LOG_LVL_ERROR, "testmain1: %s, %s, %d\n", __FILE__, __func__, __LINE__);
                }
            }
        }
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}



void add_rules_iptables()
{
    if (system(CHECK_NAME_CHAIN) != 0) {
        system(RULE_CREATE_CHAIN);
    }
    if (system(CHECK_RESOLVE_CHAIN_INPUT) != 0) {
        system(RULE_ADD_TO_INPUT);
    }
    if (system(CHECK_RESOLVE_CHAIN_OUTPUT) != 0) {
        system(RULE_ADD_TO_OUTPUT);
    }
    if (system(CHECK_RESOLVE_CHAIN_FORWARD) != 0) {
        system(RULE_ADD_TO_FORWARD);
    }
    if (system(CHECK_RULE_DNS_SPORT) != 0) {
        system(RULE_ADD_DNS_SPORT);
    }
    if (system(CHECK_RULE_DNS_DPORT) != 0) {
        system(RULE_ADD_DNS_DPORT);
    }
    LOG(LOG_LVL_DEBUG, "test_rules_iptables: %s, %s, %d\n", __FILE__, __func__, __LINE__);
}


void start_packet_capture()
{
    add_rules_iptables();
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));
    h = nfq_open();
    if (!h)
    {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }
    if (nfq_unbind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }
    if (nfq_bind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh)
    {   
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) > 0)
    {
        nfq_handle_packet(h, buf, rv);
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);
    exit(0);
}