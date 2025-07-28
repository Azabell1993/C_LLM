/*
 * @file log.h
 * @brief C 스타일 통합 로깅 유틸리티
 */

#ifndef PRLOG_H
#define PRLOG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#else
#include <sys/types.h>
#endif

#ifdef _DEBUG
#include "ename.c.inc"
#endif

#define PRLOGD_BUF_SIZE      1024    // 사용자 메시지 최대
#define PRLOG_META_BUF_SIZE   128    // 헤더용 임시 포맷
#define PRLOG_LINE_BUF_SIZE (PRLOG_META_BUF_SIZE + PRLOGD_BUF_SIZE)
#define RESOURCE_PATH "./output"

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static int log_thread_running = 1;
static pthread_t log_thread_id;

typedef struct log_node {
    char* message;
    struct log_node* next;
} log_node_t;

static log_node_t* log_head = NULL;
static log_node_t* log_tail = NULL;
static pthread_cond_t log_cv = PTHREAD_COND_INITIALIZER;

static char* get_time_string() {
    static char buffer[20];
    time_t now = time(NULL);
    struct tm tm_info;
#ifdef _WIN32
    localtime_s(&tm_info, &now);
#else
    localtime_r(&now, &tm_info);
#endif
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm_info);
    return buffer;
}

static void ensure_directory_exists(const char* dirPath) {
    struct stat st = {0};
    if (stat(dirPath, &st) == -1) {
        if (mkdir(dirPath, 0700) != 0) {
            fprintf(stderr, "[LOGGER] Directory create failed: %s\n", dirPath);
        }
    }
}

static void* log_thread_func(void* arg) {
    while (log_thread_running) {
        pthread_mutex_lock(&log_mutex);
        while (log_head == NULL && log_thread_running)
            pthread_cond_wait(&log_cv, &log_mutex);

        while (log_head) {
            log_node_t* node = log_head;
            log_head = node->next;
            if (!log_head) log_tail = NULL;
            pthread_mutex_unlock(&log_mutex);

            // 파일 이름 결정
            const char* level_start = strchr(node->message, '[') + 1;
            const char* level_end = strchr(level_start, ']');
            char level[16] = {0};
            strncpy(level, level_start, level_end - level_start);

            char filepath[256];
            ensure_directory_exists(RESOURCE_PATH);
            snprintf(filepath, sizeof(filepath), "%s/%s.log", RESOURCE_PATH, level);

            FILE* fp = fopen(filepath, "a");
            if (fp) {
                fputs(node->message, fp);
                fclose(fp);
            }

            free(node->message);
            free(node);
            pthread_mutex_lock(&log_mutex);
        }
        pthread_mutex_unlock(&log_mutex);
    }
    return NULL;
}

static void start_log_thread() {
    pthread_create(&log_thread_id, NULL, log_thread_func, NULL);
}

static void stop_log_thread() {
    pthread_mutex_lock(&log_mutex);
    log_thread_running = 0;
    pthread_cond_broadcast(&log_cv);
    pthread_mutex_unlock(&log_mutex);
    pthread_join(log_thread_id, NULL);
}

static void COUT_(const char* level, const char* func, int line, const char* format, ...) {
    char buf[PRLOG_LINE_BUF_SIZE];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

#ifdef _DEBUG
    if (strcmp(level, "ERROR") == 0 || strcmp(level, "FATAL") == 0) {
        int err = errno;
        if (err > 0 && err < MAX_ENAME && ename[err][0] != '\0') {
            strncat(buf, " | errno=", sizeof(buf) - strlen(buf) - 1);
            strncat(buf, ename[err], sizeof(buf) - strlen(buf) - 1);
        }
    }
#endif

    char* log_line = malloc(PRLOG_LINE_BUF_SIZE);
    char meta[PRLOG_META_BUF_SIZE];

#ifdef _DEBUG
    snprintf(meta, sizeof(meta), "[%s] [%s] (%s:%d) - ", level, get_time_string(), func, line);
#else
    snprintf(meta, sizeof(meta), "[%s] [%s] - ", level, get_time_string());
#endif

    snprintf(log_line, PRLOG_LINE_BUF_SIZE, "%.127s%.1022s\n", meta, buf);

#ifdef _DEBUG
    pthread_mutex_lock(&log_mutex);
    log_node_t* node = malloc(sizeof(log_node_t));
    node->message = log_line;
    node->next = NULL;
    if (log_tail) log_tail->next = node;
    else log_head = node;
    log_tail = node;
    pthread_cond_signal(&log_cv);
    pthread_mutex_unlock(&log_mutex);
#endif

#ifdef _WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (strcmp(level, "ERROR") == 0) SetConsoleTextAttribute(hConsole, 12);
    else if (strcmp(level, "FATAL") == 0) SetConsoleTextAttribute(hConsole, 206);
    else if (strcmp(level, "WARN") == 0) SetConsoleTextAttribute(hConsole, 14);
    else if (strcmp(level, "INFO") == 0) SetConsoleTextAttribute(hConsole, 10);
    else SetConsoleTextAttribute(hConsole, 7);
#endif

    printf("%s", log_line);

#ifdef _WIN32
    SetConsoleTextAttribute(hConsole, 7);
#endif

    if (strcmp(level, "FATAL") == 0)
        exit(EXIT_FAILURE);
}

#define PRLOG_I(format, ...) COUT_("INFO",  __func__, __LINE__, format, ##__VA_ARGS__)
#define PRLOG_E(format, ...) COUT_("ERROR", __func__, __LINE__, format, ##__VA_ARGS__)
#define PRLOG_F(format, ...) COUT_("FATAL", __func__, __LINE__, format, ##__VA_ARGS__)
#define PRLOG_D(format, ...) COUT_("DEBUG", __func__, __LINE__, format, ##__VA_ARGS__)
#define PRLOG_W(format, ...) COUT_("WARN",  __func__, __LINE__, format, ##__VA_ARGS__)

#endif // PRLOG_H