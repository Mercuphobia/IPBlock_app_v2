#include "log.h"
#include "file_process.h"
#include "time.h"
#include "defines.h"
#include <sys/stat.h>

const char *log_level_strings[] =
    {
        "NONE",
        "ERROR",
        "WARN",
        "DEBUG"};

unsigned char log_run_level;
char buffer[1000];
int is_first_log = 1;
int log_enable = 0;

void LOG_set_level(int level)
{
  if (level >= LOG_LVL_NONE && level <= LOG_LVL_DEBUG)
  {
    log_run_level = level;
  }
  else
  {
    log_run_level = 1;
  }
}

// void LOG_printf_info(int level, const char *format, ...)
// {
//     if (level <= log_run_level)
//     {
//         FILE *log_file;
//         va_list args;
//         time_t now;
//         struct tm *time_info;
//         char time_buffer[20];
//         struct stat log_stat;

//         if (stat(LOG_FILE_PATH, &log_stat) == 0 && log_stat.st_size >= MAX_LOG_SIZE)
//         {
//             is_first_log = 1;
//         }

//         time(&now);
//         time_info = localtime(&now);
//         strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", time_info);

//         if (is_first_log)
//         {
//             log_file = open_file(LOG_FILE_PATH, "w");
//             is_first_log = 0;
//         }
//         else
//         {
//             log_file = open_file(LOG_FILE_PATH, "a");
//         }

//         if (log_file == NULL)
//         {
//             perror("Failed to open log file");
//             exit(EXIT_FAILURE);
//         }

//         va_start(args, format);
//         vsnprintf(buffer, sizeof(buffer), format, args);
//         fprintf(log_file, "[%s] [%s] %s", time_buffer, log_level_strings[level], buffer);
//         fflush(log_file);
//         va_end(args);
//         fclose(log_file);
//     }
// }


void LOG_printf_info(int level, const char *format, ...)
{
    if (level > log_run_level)
        return;

    static long current_pos = 0;
    FILE *log_file = fopen(LOG_FILE_PATH, "r+b");
    if (log_file == NULL) {
        log_file = fopen(LOG_FILE_PATH, "w+b");
        if (log_file == NULL) {
            perror("Failed to open log file");
            return;
        }
        current_pos = sizeof(long);
        fwrite(&current_pos, sizeof(long), 1, log_file);
        fflush(log_file);
    } else {
        fseek(log_file, 0, SEEK_SET);
        fread(&current_pos, sizeof(long), 1, log_file);
        if (current_pos < sizeof(long) || current_pos >= MAX_LOG_SIZE) {
            current_pos = sizeof(long);
        }
    }

    time_t now;
    struct tm *time_info;
    char time_buffer[20];
    time(&now);
    time_info = localtime(&now);
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", time_info);

    char local_buffer[1000];
    va_list args;
    va_start(args, format);
    vsnprintf(local_buffer, sizeof(local_buffer), format, args);
    va_end(args);

    char message[1200];
    snprintf(message, sizeof(message), "[%s] [%s] %s\n", time_buffer, log_level_strings[level], local_buffer);
    int msg_size = strlen(message);

    if (current_pos + msg_size > MAX_LOG_SIZE) {
        current_pos = sizeof(long);
    }


    fseek(log_file, current_pos, SEEK_SET);
    int bytes_written = fprintf(log_file, "%s", message);
    fflush(log_file);

    current_pos += bytes_written;

    fseek(log_file, 0, SEEK_SET);
    fwrite(&current_pos, sizeof(long), 1, log_file);
    fflush(log_file);

    fclose(log_file);
}



void PRINTF(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);
}