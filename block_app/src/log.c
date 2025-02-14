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


void LOG_printf_info(int level, const char *format, ...)
{
    if (level <= log_run_level)
    {
        static long current_position = 0;
        FILE *log_file;
        va_list args;
        time_t now;
        struct tm *time_info;
        char time_buffer[20];
        struct stat log_stat;
        long header_size = 0;

        // kiem tra kich thuoc file
        if (stat(LOG_FILE_PATH, &log_stat) == 0)
        {
            // doc gia tri current_pos tu file
            FILE *read_file = fopen(LOG_FILE_PATH, "r");
            if (read_file)
            {   
               // bo sung truong hop k doc duoc thi in ra in hoac ket thuc chuong trinh
                if (fscanf(read_file, "current_position = %ld\n", &current_position) != 1) {
                    printf("Error reading file!\n");
                }
                fscanf(read_file, "current_position = %ld\n", &current_position);

                header_size = ftell(read_file); // xac dinh vi tri sau header
                fclose(read_file);
            }

            // file day quay con tro lai dau file
            if (log_stat.st_size >= MAX_LOG_SIZE)
            {
                current_position = header_size; // quay con tro lai sau header
            }
        }
        else
        {
            // Nếu file chưa tồn tại, tạo mới
            current_position = 0;
        }

        time(&now);
        time_info = localtime(&now);
        strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", time_info);


        log_file = fopen(LOG_FILE_PATH, "r+");
        if (log_file == NULL)
        {
            log_file = fopen(LOG_FILE_PATH, "w"); // neu k ton tai tao file moi
            if (log_file == NULL)
            {
                perror("Failed to open log file");
                exit(EXIT_FAILURE);
            }
            fprintf(log_file, "current_position = %ld\n", header_size);
            fflush(log_file);
            current_position = header_size;
        }

        // dinh dang noi dung log
        char buffer[1000];
        va_start(args, format);
        vsnprintf(buffer, sizeof(buffer), format, args);
        int msg_size = snprintf(NULL, 0, "[%s] [%s] %s\n", time_buffer, log_level_strings[level], buffer);
        va_end(args);

        // cong kich thuoc neu lon hon thi quay lai
        if (current_position + msg_size >= MAX_LOG_SIZE)
        {
            current_position = header_size; // neu qua kich thuoc quay lai dau file
        }

        // di chuyen den vi tri can ghi
        fseek(log_file, current_position, SEEK_SET);
        char buffer_temp[1000] = {0};
        fgets(buffer_temp, sizeof(buffer_temp), log_file);

        int msg_size_old = strlen(buffer_temp);

        // ghi de toanf bo noi dung cu bang khoang trang de tranh du ki tu
        fseek(log_file, current_position, SEEK_SET);
        for (int i = 0; i < msg_size_old; i++) {
            fputc(' ', log_file);
        }
        fflush(log_file);

        // ghi log moi vao
        fseek(log_file, current_position, SEEK_SET);
        fprintf(log_file, "[%s] [%s] %s\n", time_buffer, log_level_strings[level], buffer);
        fflush(log_file);

        // update current_pos
        current_position = ftell(log_file);

        // ghi lai current_pos
        fseek(log_file, 0, SEEK_SET);
        fprintf(log_file, "current_position = %ld\n", current_position);
        fflush(log_file);
        fclose(log_file);
    }
}


void PRINTF(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);
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