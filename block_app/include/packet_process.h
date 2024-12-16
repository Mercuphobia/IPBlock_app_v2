#ifndef PACKET_PROCESS_H
#define PACKET_PROCESS_H

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

void cleanup();
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
void add_rules_iptables();
void start_packet_capture();
//static u_int32_t process_packet(struct nfq_data *tb);


#endif