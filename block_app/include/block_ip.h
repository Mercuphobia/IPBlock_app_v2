#ifndef BLOCK_IP_H
#define BLOCK_IP_H


void get_list();
void delete_iptable_rules_chain_and_ipset();
long convert_to_seconds(const char *day, const char *time);
int get_day_number(const char *day);
void run_block_ip();
#endif // BLOCK_IP_H