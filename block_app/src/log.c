#include "log.h"
#include "file_process.h"
#include "time.h"
// #define LOG_FILE_PATH "./data/log.txt"

#define LOG_FILE_PATH "../../block_app/data/log.txt"

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

void log_set_level(int level)
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


void printf_log(int level, const char *format, ...)
{  
  if (level <= log_run_level)
  {
    FILE *log_file;
    if (is_first_log)
    {
      log_file = open_file(LOG_FILE_PATH, "w");
      is_first_log = 0;
    }
    else
    {
      log_file = open_file(LOG_FILE_PATH, "a");
    }

    if (log_file == NULL)
    {
      perror("Failed to open log file");
      return;
    }
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    //printf("[%s] %s", log_level_strings[level], buffer);
    fprintf(log_file, "[%s] %s", log_level_strings[level], buffer);
    fflush(log_file);
    va_end(args);
    fclose(log_file);
  }
}