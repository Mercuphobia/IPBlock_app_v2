#ifndef FILE_PROCESS_H
#define FILE_PROCESS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Describes: Function that opens a file with the specified mode and checks whether the file
 *            opening was successful or not
 *
 * Parameter:
 *   file_name: Folder need to open
 *   mode: Mode to opend file
 *
 * Return:
 *   If the file opens successfully, returns a pointer to the opened file.
 *   If the file cannot be opened, returns NULL.
 */
FILE *open_file(const char *file_name, const char *mode);

/* Describe: Function that creates an empty file
 *
 * Parameters:
 *   filename: Source file to copy
 *
 * Output:
 *   If the file cannot be opened for creation, the function prints an error message and stops execution. If successful,
 *   an empty file is created and the function terminates without a return value.
 */
void FP_create_empty_file(const char *filename);

/* Describe: Copy the contents of one file to another file
 *
 * Parameters:
 *   input file: Source file to copy
 *   output file: Destination file to copy data to
 *
 * Output:
 *   If the function executes successfully, it will copy the contents from the source file to the destination file without
 *   Exit the program if the source or destination file cannot be opened, so if there is an error,
 *   the function will stop the program and print the error.
 */
void FP_copy_file(const char *input_file, const char *output_file);

/* Describe: Initialize file paths by reading their values from a configuration file.
 *
 * This function reads the values of several configuration keys from a configuration file and updates
 * the corresponding global variables with these values. If a key is not found in the configuration file,
 * the global variable retains its default value.
 *
 * Parameters:
 *   None
 *
 * Output:
 *   None
 */
void FP_init_path();

#endif