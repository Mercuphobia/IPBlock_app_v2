#define _POSIX_C_SOURCE 2
#include <stdio.h>
#include <stdlib.h>
#include "log.h"

void transfer_data(const char *input_file, const char *output_file) {
    FILE *fp1, *fp2;
    char buffer[128];

    char command1[256];
    snprintf(command1, sizeof(command1), "cat %s", input_file);
    fp1 = popen(command1, "r");
    if (fp1 == NULL) {
        perror("Failed to run input command");
        exit(1);
    }

    char command2[256];
    snprintf(command2, sizeof(command2), "cat > %s", output_file);
    fp2 = popen(command2, "w");
    if (fp2 == NULL) {
        perror("Failed to run output command");
        pclose(fp1);
        exit(1);
    }

    while (fgets(buffer, sizeof(buffer), fp1) != NULL) {
        fputs(buffer, fp2);
    }

    pclose(fp1);
    pclose(fp2);
}
