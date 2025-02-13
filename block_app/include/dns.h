#ifndef DNS_H
#define DNS_H

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

struct dns_header
{
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

struct dns_queries
{
    unsigned short qname;
    unsigned short qtype;
    unsigned short qclass;
};

struct dns_answer
{
    unsigned short name;
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short data_len;
    unsigned int ip_addr;
};

/* Describes: Calculate the length of a DNS query from input data as a byte array
 *
 * Parameter:
 *   dns query: This is a pointer to a byte array representing a DNS query.
 *
 * Return:
 *  The return value is the total length (in bytes) of the entire DNS query, including:
 *      The domain name (including length bytes and the terminating zero byte).
 *      An additional 4 bytes for Type and Class.
 */
int DNS_get_dns_query_length(unsigned char *dns_query);

/* Describes: Decode the domain name stored in a DNS packet
 *
 * Parameter:
 *   dns_packet: This is a pointer to the DNS packet containing the data to be decoded.
 *               The DNS packet includes header, question, answer, and other pieces of data.
 *   buffer: This is a pointer to a character array into which the decoded domain name will be saved
 *   offset: This is a pointer to an integer variable, used to return the next position (offset) after decoding
 *           the domain name. This value helps locate the next piece of data in the DNS packet.
 *   start: This is the initial index in the DNS packet from which decoding of the domain name begins.
 *
 * Output:
 *  The domain name string (DNS name) after decoding is stored in the buffer array
 *  The offset variable will be updated to point to the first byte after the decoded domain name
 */
void DNS_decode_dns_name_answer(unsigned char *dns_packet, unsigned char *buffer, int *offset, int start);

/* Describes: Function designed to process the DNS answer and save
 *            the IP address associated with the domain name to a specific directory.
 *            Specifically Determine the length of the domain name in the DNS answer,
 *            extract information from the DNS answer, read the list of websites to block,
 *            process each domain name and save the IP to the directory.
 *
 * Parameter:
 *   dns_answer: Contains DNS answer data from the DNS packet. This is the response data from
 *               the DNS server that contains information about the response type, data length,
 *               and IP value or corresponding information.
 *   dns_payload_content: Is the full payload of the DNS packet, including header and data.
 *                        This parameter can be used to extract the full domain name from the DNS response
 *                        using offsets or pointers in the DNS response.
 *   folder: Folder where you want to store IP addresses. Each domain name will have its own file
 *           in the corresponding folder or subfolders
 *   is_domain: Check if the folder where the data is to be saved is a folder named domain. 
 *              If not, save it to another folder
 *
 * Output:
 *  The result of the function is the side effects, specifically:
 *      If a matching IP address is found, it will be written to a file in the specified folder.
 *      If no domain name matches or the file is not found, the function will do nothing more.
 */
void DNS_process_dns_answer_and_save_ip_in_folder(unsigned char *dns_answer, unsigned char *dns_payload_content,
                                              unsigned char *folder, int is_domain);

#endif
