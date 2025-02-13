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
#include "defines.h"

#define RULE_CREATE_CHAIN "iptables -N RESOLVE_CHAIN"

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

/* Description: This function processes DNS packets captured from the Netfilter Queue.
 *              It extracts the IP and UDP headers, verifies if the packet is a DNS response,
 *              and then analyzes the DNS answers to extract and store IP addresses.
 *
 * Parameters:
 *   - qh: Pointer to the Netfilter queue handle.
 *   - nfmsg: Pointer to Netfilter message (not used in this function).
 *   - nfa: Pointer to the packet data from the Netfilter queue.
 *   - data: Additional data (not used in this function).
 *
 * Return:
 *   - Returns `NF_ACCEPT` to allow the packet to continue through the network stack.
 *
 * Notes:
 *   - This function only processes UDP packets on the DNS port.
 *   - It extracts and processes DNS answers if at least one answer record is present.
 */
static int process_dns_packets(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{   
    //LOG(LOG_LVL_DEBUG, "%s, %d: Start \n", __func__, __LINE__);

    u_int32_t id;
    struct nfqnl_msg_packet_hdr *packet_header;
    unsigned char *packet_data, *dns_size, *dns_payload_content, *dns_query, *dns_answer;
    int payload_size, number_of_answer, query_length, dns_payload_size, name_length;
    struct iphdr *ip_header;
    struct udphdr *udp_header;
    struct dns_header *dns;
    unsigned short data_len;

    packet_header = nfq_get_msg_packet_hdr(nfa);
    if (packet_header)
    {
        id = ntohl(packet_header->packet_id);
    }

    payload_size = nfq_get_payload(nfa, &packet_data);
    if (payload_size >= 0)
    {   
        ip_header = (struct iphdr *)packet_data;

        if (ip_header->protocol == IPPROTO_UDP)
        {
            udp_header = (struct udphdr *)(packet_data + (ip_header->ihl * 4));
            struct in_addr src_ip = {ip_header->saddr};
            struct in_addr dest_ip = {ip_header->daddr};

            if (ntohs(udp_header->source) == PORT_DNS)
            {
                dns_size = (unsigned char *)(packet_data + (ip_header->ihl * 4) + sizeof(struct udphdr));
                dns = (struct dns_header *)dns_size;

                if (ntohs(dns->qdcount) == 1 && ntohs(dns->ancount) > 0)
                {
                    dns_payload_content = (unsigned char *)(dns_size + sizeof(struct dns_header));
                    dns_payload_size = payload_size - (sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header));
                    dns_query = dns_size + sizeof(struct dns_header);
                    query_length = DNS_get_dns_query_length(dns_query);
                    dns_answer = dns_query + query_length;
                    number_of_answer = ntohs(dns->ancount);

                    for(int i=0;i<number_of_answer;i++)
                    {
                        name_length = 0;
                        DNS_process_dns_answer_and_save_ip_in_folder(dns_answer, dns_payload_content, DOMAIN_DIR, 1);
                        DNS_process_dns_answer_and_save_ip_in_folder(dns_answer, dns_payload_content, IP_DB_DIR, 0);

                        if ((dns_answer[0] & 0xC0) == 0xC0) {
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

                        data_len = ntohs(*(unsigned short *)(dns_answer + name_length + 8));
                        dns_answer += name_length + 10 + data_len;
                    }
                }
            }
        }
    }

    //LOG(LOG_LVL_DEBUG, "%s, %d: End \n", __func__, __LINE__);

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

/* Description: Adds necessary iptables rules to manage network traffic by checking and creating chains if they do not exist.
 *
 * Parameters:
 * - None.
 *
 * Output:
 * - Executes system commands to check for the existence of iptables chains and rules, 
 *   and adds them if they are missing.
 */
void add_rules_iptables()
{   
    LOG(LOG_LVL_DEBUG, "%s, %d: Start \n", __func__, __LINE__);

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

    LOG(LOG_LVL_DEBUG, "%s, %d: End \n", __func__, __LINE__);
}

void PP_start_packet_capture()
{   
    LOG(LOG_LVL_DEBUG, "%s, %d: Start \n", __func__, __LINE__);

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;

    add_rules_iptables();
    char buf[4096] __attribute__((aligned));
    
    h = nfq_open();

    if (!h)
    {
        fprintf(stderr, "error during nfq_open()\n");
        LOG(LOG_LVL_ERROR, "%s, %d: End program. error during nfq_open(). \n", __func__, __LINE__);
        exit(1);
    }
    if (nfq_unbind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        LOG(LOG_LVL_ERROR, "%s, %d: End program. error during nfq_unbind_pf() \n", __func__, __LINE__);
        exit(1);
    }
    if (nfq_bind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        LOG(LOG_LVL_ERROR, "%s, %d: End program. error during nfq_bind_pf() \n", __func__, __LINE__);
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &process_dns_packets, NULL);
    if (!qh)
    {   
        fprintf(stderr, "error during nfq_create_queue()\n");
        LOG(LOG_LVL_ERROR, "%s, %d: End program. error during nfq_create_queue() \n", __func__, __LINE__);
        exit(1);
    }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        fprintf(stderr, "can't set packet_copy mode\n");
        LOG(LOG_LVL_ERROR, "%s, %d: End program. can't set packet_copy mode \n", __func__, __LINE__);
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) > 0)
    {
        nfq_handle_packet(h, buf, rv);
    }

    PRINTF("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    PRINTF("closing library handle\n");
    nfq_close(h);
    exit(0);
}