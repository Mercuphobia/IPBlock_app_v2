#ifndef PARSER_OPTION_H
#define PARSER_OPTION_H


/* Description: Parses command-line options and arguments to configure the application's behavior.
 *
 * Parameters:
 * - argc: Number of command-line arguments.
 * - argv: Array of command-line argument strings.
 *
 * Output:
 * - Processes command-line options:
 *   - `-h` or `--help`: Displays usage information.
 *   - `-d <loglevel>` or `--debug <loglevel>`: Sets the logging level.
 * - Prints any non-option arguments.
 */
void PO_parsers_option(int argc, char *argv[]);

#endif // PARSER_OPTION_H

