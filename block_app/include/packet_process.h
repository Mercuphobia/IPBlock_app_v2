#ifndef PACKET_PROCESS_H
#define PACKET_PROCESS_H


/* Description: This function sets up and starts capturing network packets using the Netfilter Queue library (libnetfilter_queue).
 *              It attaches to a specific Netfilter queue to intercept packets, processes those packets using a callback function,
 *              and then releases resources when done.
 *
 * Parameters:
 *   None.
 *
 * Output:
 *   - Intercepts network packets and processes them based on the callback `process_dns_packets`.
 *   - Writes diagnostic messages to the console if errors occur.
 *
 * Notes:
 *   - This function requires iptables rules to redirect packets to the Netfilter queue.
 *   - Exits the program on error.
 */
void PP_start_packet_capture();

#endif