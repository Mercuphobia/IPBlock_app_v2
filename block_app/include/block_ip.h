#ifndef BLOCK_IP_H
#define BLOCK_IP_H

/* Describe: takes a string representing a day of the week 
 *           and returns an integer corresponding to the ordinal of that day of the week
 *
 * Parameters:
 *   day: Is a constant pointer to an input string containing the day of the week name.
 * 
 * Return:
 *      0 - 6: Corresponds to the days of the week from Monday to Sunday.
 *      -1: When the input string is not a valid date name.
 */
int BI_get_day_number(const char *day);

/* Describes: This function is designed to run the website blocking part by ip address, the steps include:
 *                  Create chain and add chain to input, output or forward 
 *                  Browse the list of websites to block
 *                  Check if there is data about that website, if there is then block by adding data about 
 *                  that website's ip to ipset and add that ipset rules and the created chain
 *
 * Parameter:
 *
 * Output:
 * Chains are created and added to input, output, forward
 * Ipset rules are added to the chain if there is data from that website
 */
void BI_run_block_ip();
#endif // BLOCK_IP_H