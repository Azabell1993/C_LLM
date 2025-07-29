/**
 * @file safe_arithmetic_ops.c
 * @brief 유저레벨 커널 통합 엔진 (안전 산술 연산 / 동기화 / 스마트 포인터 / 네트워크 / 스레드 / 프로세스 / LLM 포함)
 *
 * - 안전 산술 연산: GCC 내장 오버플로우 감지 또는 수동 방식으로 정수 연산의 안전성 확보
 * - 스레드/프로세스 관리**: POSIX 기반 pthread와 fork를 이용한 병렬 처리 예제
 * - 동기화 기법: 뮤텍스와 세마포어를 이용한 임계영역 보호 및 자원 제한 처리
 * - 스마트 포인터: 참조 카운팅 기반 스마트 포인터 구현 (retain/release 방식)
 * - 네트워크 정보 처리: 로컬 호스트의 IPv4 주소 및 패밀리 정보 조회
 * - 연결 리스트 구조체: 기본적인 push/pop/destroy 구현 제공
 * - LLM 통합: LLaMA 기반 모델을 불러와 질의 응답 수행 (llm_engine.h 연동 필요)
 * - 벤치마크 및 테스트: 다양한 오버플로우 검증 로직에 대한 성능 비교 가능
 * - TaskManager: 상황별 동기화 방식 자동 선택(뮤텍스 vs 세마포어)
 *
 * 명령어 인자 지원: `run`, `v`, `f`, `s`, `h`, `c`, `llm`, `--help`
 *
 * 전체 구조는 실전 유저레벨 OS 커널 시뮬레이션/테스트/교육용으로 활용 가능하며,
 * 필요한 기능을 별도로 분리하거나 확장하여 단위 모듈로 재사용할 수 있도록 설계되었습니다.
 *
 * @author
 *  Azabell1993 (https://github.com/Azabell1993)
 * @date
 *  2025
 * @copyright
 *  Copyright 2025. All rights reserved.
 */

#include "safe_arithmetic_ops.h"
#include "llm_engine.h"
#include "log.h"

/**
 * @brief 메모리 핸들을 해제합니다.
 * 이 함수는 핸들을 리스트에서 제거하고, 메모리를 해제합니다.
 * 주의: 핸들이 매핑되어 있으면 언매핑 후 해제해야 합니다.
 * @return void
 */
void destroy_mem_handle(MemHandle *mh) {
    pthread_mutex_lock(&g_mem_handles.lock);
    LIST_REMOVE(mh, entries);
    pthread_mutex_unlock(&g_mem_handles.lock);
    free(mh->addr);
    free(mh);
}

/**
 * @brief 핸들 매핑 함수
 * 이 함수는 핸들이 매핑되어 있지 않은 경우 매핑을 수행합니다.
 * 매핑 상태를 변경하고, 성공 여부를 반환합니다.
 * @return 성공 시 1, 실패 시 0
 */
int map_mem_handle(MemHandle *mh) {
    if (mh->mapped) return 0;
    mh->mapped = 1;
    // 실제 mmap 대신 malloc 사용
    return 1;
}

/**
 * @brief 핸들 언매핑 함수
 * 이 함수는 핸들이 매핑되어 있는 경우 언매핑을 수행합니다.
 * 매핑 상태를 변경하고, 성공 여부를 반환합니다.
 * @return 성공 시 1, 실패 시 0
 */
int unmap_mem_handle(MemHandle *mh) {
    if (!mh->mapped) return 0;
    mh->mapped = 0;
    return 1;
}

/**
 * @brief 핸들 기반 안전 덧셈 함수
 * 이 함수는 핸들로 관리되는 메모리에서 안전하게 덧셈을 수행합니다.
 * 핸들이 매핑되어 있어야 하며, 오버플로우를 체크합니다.
 * @param mh 메모리 핸들
 * @param offset 덧셈을 수행할 오프셋
 * @param value 덧셈할 값
 * @return 성공 시 1, 실패 시 0
 */
int handle_safe_add(MemHandle *mh, int offset, int value) {
    if (!mh->mapped || offset < 0 || offset + sizeof(int) > mh->size) return 0;
    int *ptr = (int *)((char*)mh->addr + offset);
    int res;
    if (!SAFE_OP(res, =, *ptr, +, value)) return 0;
    *ptr = res;
    return 1;
}

/**
 * @brief 핸들 기반 메모리 복사 함수
 * 이 함수는 두 개의 메모리 핸들 간에 데이터를 복사합니다.
 * 핸들이 매핑되어 있어야 하며, 복사할 크기가 핸들의 크기를 초과하지 않아야 합니다.
 * @param dst 대상 핸들
 * @param src 소스 핸들
 * @param size 복사할 크기
 * @return 성공 시 1, 실패 시 0
 */
int handle_memcpy(MemHandle *dst, MemHandle *src, size_t size) {
    if (!dst->mapped || !src->mapped || size > dst->size || size > src->size) return 0;
    memcpy(dst->addr, src->addr, size);
    return 1;
}

/**
 * @brief 핸들 벤치마크를 실행합니다.
 * 이 함수는 두 개의 메모리 핸들을 생성하고, 안전한 덧셈과 복사를 수행합니다.
 * 핸들을 매핑하고 언매핑하며, 결과를 출력합니다.
 * @return void
 */
void run_handle_bench(void) {
    MemHandle *mh1 = create_mem_handle(4096);
    MemHandle *mh2 = create_mem_handle(4096);
    map_mem_handle(mh1);
    map_mem_handle(mh2);

    int *p = (int*)mh1->addr;
    *p = 100000;
    handle_safe_add(mh1, 0, 100000); // 안전 덧셈

    handle_memcpy(mh2, mh1, sizeof(int)); // 복사

    user_safe_printf("[핸들 벤치] mh1[0]=%d, mh2[0]=%d\n", *(int*)mh1->addr, *(int*)mh2->addr);

    unmap_mem_handle(mh1);
    unmap_mem_handle(mh2);
    destroy_mem_handle(mh1);
    destroy_mem_handle(mh2);
}

/**
 * @brief 모든 메모리 핸들을 해제합니다.
 * 이 함수는 프로그램 종료 시 호출되어야 합니다.
 * 메모리 누수를 방지하기 위해 모든 핸들을 순회하며 해제합니다.
 * @return void
 */
void destroy_all_mem_handles(void) {
    pthread_mutex_lock(&g_mem_handles.lock);
    MemHandle *mh, *tmp;
    for (mh = LIST_FIRST(&g_mem_handles.head); mh != NULL; mh = tmp) {
        tmp = LIST_NEXT(mh, entries);
        destroy_mem_handle(mh);
    }
    pthread_mutex_unlock(&g_mem_handles.lock);
}

const char * llama_print_system_info(void) {
    static char s[4096];
    s[0] = '\0';

    size_t n = 0;
    size_t count = ggml_backend_reg_count();
    for (size_t i = 0; i < count; i++) {
        void *reg = ggml_backend_reg_get(i);
        ggml_backend_get_features_t get_features_fn =
            (ggml_backend_get_features_t)(void *)ggml_backend_reg_get_proc_address(reg, "ggml_backend_get_features");
        if (get_features_fn) {
            ggml_backend_feature *features = get_features_fn(reg);
            n += snprintf(s + n, sizeof(s) - n, "%s : ", (const char *)ggml_backend_reg_name(reg));
            for (; features->name; features++) {
                n += snprintf(s + n, sizeof(s) - n, "%s = %s | ", features->name, features->value);
            }
            n += snprintf(s + n, sizeof(s) - n, "\n");
        }
    }
    return s;
}

/**
 * @brief 로컬 네트워크 정보를 가져오는 함수
 *
 * @return NetworkInfo 로컬 네트워크 정보가 저장된 구조체
 */
NetworkInfo get_local_network_info() {
    struct addrinfo hints, *res;
    NetworkInfo net_info;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
        perror("getaddrinfo 실패");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), net_info.ip, INET_ADDRSTRLEN);
    net_info.family = res->ai_family;

    freeaddrinfo(res);
    return net_info;
}

/**
 * @brief 스마트 포인터를 생성하는 함수 (가변 인자 사용)
 *
 * @param size 할당할 메모리 크기
 * @param ... 가변 인자 리스트 (초기값)
 * @return SmartPtr 스마트 포인터 구조체
 */
SmartPtr create_smart_ptr(size_t size, ...) {
    SmartPtr sp;
    sp.ptr = malloc(size);
    sp.ref_count = (int *)malloc(sizeof(int));
    *(sp.ref_count) = 1;
    sp.mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(sp.mutex, NULL);

    va_list args;
    va_start(args, size);

    if (size == sizeof(int)) {
        int value = va_arg(args, int);
        *(int *)sp.ptr = value;
    } else if (size == sizeof(char) * MAX_STRING_SIZE) {
        const char *str = va_arg(args, const char *);
        strncpy((char *)sp.ptr, str, MAX_STRING_SIZE);
    }

    va_end(args);
    return sp;
}

/**
 * @brief 스마트 포인터의 참조 카운트를 증가시키는 함수
 *
 * @param sp 증가시킬 스마트 포인터
 */
void retain(SmartPtr *sp) {
    pthread_mutex_lock(sp->mutex);
    (*(sp->ref_count))++;
    pthread_mutex_unlock(sp->mutex);
}

/**
 * @brief 스마트 포인터의 참조 카운트를 감소시키고 필요시 메모리를 해제하는 함수
 *
 * @param sp 해제할 스마트 포인터
 */
void release(SmartPtr *sp) {
    int should_free = 0;

    pthread_mutex_lock(sp->mutex);
    (*(sp->ref_count))--;
    safe_kernel_printf("Smart pointer released (ref_count: %d)\n", *(sp->ref_count));

    if (*(sp->ref_count) == 0) {
        should_free = 1;
        safe_kernel_printf("Reference count is 0, freeing memory...\n");
    }

    pthread_mutex_unlock(sp->mutex);

    if (should_free) {
        free(sp->ptr);
        sp->ptr = NULL;
        free(sp->ref_count);
        sp->ref_count = NULL;

        pthread_mutex_destroy(sp->mutex);
        free(sp->mutex);
        sp->mutex = NULL;

        safe_kernel_printf("Memory has been freed\n");
    }
}

/**
 * @brief 스레드 안전한 출력 함수
 *
 * @param format 출력할 메시지 형식
 */
static void safe_kernel_printf(const char *format, ...) {
    va_list args;
    va_start(args, format);

    pthread_mutex_lock(&print_mutex);
    vprintf(format, args);
    pthread_mutex_unlock(&print_mutex);

    if(errno != 0) {
        kernel_errExit("Failed to print message");
    }

    va_end(args);
}

/**
 * @brief 오류 메시지를 출력하고 프로그램을 종료하는 함수
 *
 * @param format 출력할 오류 메시지 형식
 */
static void kernel_errExit(const char *format, ...) {
    va_list argList;
    va_start(argList, format);

    safe_kernel_printf("ERROR: %s\n", format);
    fprintf(stderr, "errno: %d (%s)\n", errno, strerror(errno));
    fflush(stdout);
    va_end(argList);

    terminate(true);
}

/**
 * @brief 프로그램 종료 처리 함수
 *
 * @param useExit3 true면 exit() 호출, false면 _exit() 호출
 */
static void terminate(bool useExit3) {
    char *s = getenv("EF_DUMPCORE");

    if (s != NULL && *s != '\0')
        abort();
    else if (useExit3)
        exit(EXIT_FAILURE);
    else
        _exit(EXIT_FAILURE);
}

/**
 * @brief 스레드에서 수행할 함수
 *
 * @param arg 스레드 인수 (스레드 번호)
 * @return NULL
 */
void* thread_function(void* arg) {
    int thread_num = *((int*)arg);

    NetworkInfo net_info = get_local_network_info();

    safe_kernel_printf("Thread %d: 시작 - 로컬 IP 주소: %s\n", thread_num, net_info.ip);

    sleep(1);

    safe_kernel_printf("Thread %d: 종료 - 주소 패밀리: %d\n", thread_num, net_info.family);
    return NULL;
}

/**
 * @brief 소켓을 사용한 메시지 전송 및 수신 함수
 *
 * @param sock_fd 소켓 파일 디스크립터
 * @param message 전송할 메시지
 * @param response 수신할 응답
 * @param response_size 응답 버퍼 크기
 */
static void kernel_socket_communication(int sock_fd, const char *message, char *response, size_t response_size) {
    if (write(sock_fd, message, strlen(message)) == -1) {
        safe_kernel_printf("Failed to send message through socket");
        kernel_errExit("Failed to send message through socket");
    }

    ssize_t bytes_read = read(sock_fd, response, response_size - 1);
    if (bytes_read == -1) {
        safe_kernel_printf("Failed to receive message from socket");
        kernel_errExit("Failed to receive message from socket");
    }

    response[bytes_read] = '\0';
}

/**
 * @brief 자식 프로세스를 대기하는 함수
 *
 * @param pid 자식 프로세스의 PID
 */
static void kernel_wait_for_process(pid_t pid) {
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        safe_kernel_printf("Failed to wait for process");
        kernel_errExit("Failed to wait for process");
    } else {
        safe_kernel_printf("Child process exited with status %d\n", status);
    }
}

/**
 * @brief 스레드를 생성하는 함수
 *
 * @param thread 생성할 스레드의 포인터
 * @param start_routine 스레드에서 실행할 함수
 * @param arg 스레드 함수에 전달할 인수
 */
static void kernel_create_thread(pthread_t *thread, void *(*start_routine)(void *), void *arg) {
    int err = pthread_create(thread, NULL, start_routine, arg);
    if (err != 0) {
        safe_kernel_printf("Failed to create thread");
        kernel_errExit("Failed to create thread");
    } else {
        safe_kernel_printf("Thread created successfully\n");
    }
}

/**
 * @brief 스레드 종료를 대기하는 함수
 *
 * @param thread 종료 대기할 스레드
 */
static void kernel_join_thread(pthread_t thread) {
    int err = pthread_join(thread, NULL);
    if (err != 0) {
        safe_kernel_printf("Failed to join thread");
        kernel_errExit("Failed to join thread");
    } else {
        safe_kernel_printf("Thread joined successfully\n");
    }
}

#ifndef SAFE_ASSERT
#   define SAFE_ASSERT(expr) assert(expr)
#endif

static int g_use_gcc_builtins = 0;

#if !defined(USE_GCC_OVERFLOW_BUILTINS) && __GNUC__ >= 5
#   define USE_GCC_OVERFLOW_BUILTINS g_use_gcc_builtins
#else
#   define USE_GCC_OVERFLOW_BUILTINS 0
#endif


// Range tables for overflow checking
static const struct { intmax_t min, max; } range_int = { INT_MIN, INT_MAX };
static const struct { intmax_t min, max; } range_long = { LONG_MIN, LONG_MAX };
static const struct { uintmax_t max; } range_uint = { UINT_MAX };
static const struct { uintmax_t max; } range_ulong = { ULONG_MAX };
#if HAS_LONG_LONG
static const struct { intmax_t min, max; } range_llong = { LLONG_MIN, LLONG_MAX };
static const struct { uintmax_t max; } range_ullong = { ULLONG_MAX };
#endif

#define _CHECKED_OP_ADD(res, v1, v2, r) (USE_GCC_OVERFLOW_BUILTINS \
    ? !__builtin_add_overflow(v1, v2, res) \
    : (((v2) > 0 && (v1) > ((r).max - (v2))) \
        || ((v2) < 0 && (v1) < ((r).min - (v2))) \
        ? 0 : (*(res) = (v1) + (v2), 1)))

#define _CHECKED_OP_SUB(res, v1, v2, r) (USE_GCC_OVERFLOW_BUILTINS \
    ? !__builtin_sub_overflow(v1, v2, res) \
    : (((v2) > 0 && (v1) < ((r).min + (v2))) \
        || ((v2) < 0 && (v1) > ((r).max + (v2))) \
        ? 0 : (*(res) = (v1) - (v2), 1)))

#define _CHECKED_OP_MULT(res, v1, v2, r) (USE_GCC_OVERFLOW_BUILTINS \
    ? !__builtin_mul_overflow(v1, v2, res) \
    : ((v1) > 0 \
        ? ((v2) > 0 ? (v1) > ((r).max / (v2)) : (v2) < ((r).min / (v1))) \
        : ((v1) < 0 \
            ? ((v2) > 0 ? (v1) < ((r).min / (v2)) : ((v1) != 0 && (v2) < ((r).max / (v1)))) \
            : 0)) \
    ? 0 : (*(res) = (v1) * (v2), 1))

#define _CHECKED_OP_DIV(res, v1, v2, r) (((v2) == 0 || ((v1) == (r).min && (v2) == -1)) \
    ? 0 : (*(res) = (v1) / (v2), 1))

#define _CHECKED_OP_UADD(res, v1, v2, r) (((v1) > ((r).max - (v2))) \
    ? 0 : (*(res) = (v1) + (v2), 1))

#define _CHECKED_OP_USUB(res, v1, v2) (((v1) < (v2)) \
    ? 0 : (*(res) = (v1) - (v2), 1))

#define _CHECKED_OP_UMULT(res, v1, v2, r) ((((v2) != 0) && ((v1) > ((r).max / (v2)))) \
    ? 0 : (*(res) = (v1) * (v2), 1))

#define _CHECKED_OP_UDIV(res, v1, v2) (((v2) == 0) \
    ? 0 : (*(res) = (v1) / (v2), 1))

// --- Core Safe Arithmetic Operations ---

// Type-specific handler functions
static inline int checked_op_handler_int(int *lval, const char* as, intmax_t first, const char* op, intmax_t second) {
    int temp_res;
    int *res = &temp_res;
    int ok = 0;
    if (op[0] == '*') ok = _CHECKED_OP_MULT(res, first, second, range_int);
    else if (op[0] == '/') ok = _CHECKED_OP_DIV(res, first, second, range_int);
    else if (op[0] == '+') ok = _CHECKED_OP_ADD(res, first, second, range_int);
    else if (op[0] == '-') ok = _CHECKED_OP_SUB(res, first, second, range_int);
    if (!ok) return 0;
    if (as[0] == '=') *lval = temp_res;
    else if (as[0] == '+') return _CHECKED_OP_ADD(lval, *lval, temp_res, range_int);
    else if (as[0] == '-') return _CHECKED_OP_SUB(lval, *lval, temp_res, range_int);
    else if (as[0] == '*') return _CHECKED_OP_MULT(lval, *lval, temp_res, range_int);
    else if (as[0] == '/') return _CHECKED_OP_DIV(lval, *lval, temp_res, range_int);
    return 1;
}
static inline int checked_op_handler_uint(unsigned int *lval, const char* as, uintmax_t first, const char* op, uintmax_t second) {
    unsigned int temp_res;
    unsigned int *res = &temp_res;
    int ok = 0;
    if (op[0] == '*') ok = _CHECKED_OP_UMULT(res, first, second, range_uint);
    else if (op[0] == '/') ok = _CHECKED_OP_UDIV(res, first, second);
    else if (op[0] == '+') ok = _CHECKED_OP_UADD(res, first, second, range_uint);
    else if (op[0] == '-') ok = _CHECKED_OP_USUB(res, first, second);
    if (!ok) return 0;
    if (as[0] == '=') *lval = temp_res;
    else if (as[0] == '+') return _CHECKED_OP_UADD(lval, *lval, temp_res, range_uint);
    else if (as[0] == '-') return _CHECKED_OP_USUB(lval, *lval, temp_res);
    else if (as[0] == '*') return _CHECKED_OP_UMULT(lval, *lval, temp_res, range_uint);
    else if (as[0] == '/') return _CHECKED_OP_UDIV(lval, *lval, temp_res);
    return 1;
}
static inline int checked_op_handler_long(long *lval, const char* as, intmax_t first, const char* op, intmax_t second) {
    long temp_res;
    long *res = &temp_res;
    int ok = 0;
    if (op[0] == '*') ok = _CHECKED_OP_MULT(res, first, second, range_long);
    else if (op[0] == '/') ok = _CHECKED_OP_DIV(res, first, second, range_long);
    else if (op[0] == '+') ok = _CHECKED_OP_ADD(res, first, second, range_long);
    else if (op[0] == '-') ok = _CHECKED_OP_SUB(res, first, second, range_long);
    if (!ok) return 0;
    if (as[0] == '=') *lval = temp_res;
    else if (as[0] == '+') return _CHECKED_OP_ADD(lval, *lval, temp_res, range_long);
    else if (as[0] == '-') return _CHECKED_OP_SUB(lval, *lval, temp_res, range_long);
    else if (as[0] == '*') return _CHECKED_OP_MULT(lval, *lval, temp_res, range_long);
    else if (as[0] == '/') return _CHECKED_OP_DIV(lval, *lval, temp_res, range_long);
    return 1;
}
static inline int checked_op_handler_ulong(unsigned long *lval, const char* as, uintmax_t first, const char* op, uintmax_t second) {
    unsigned long temp_res;
    unsigned long *res = &temp_res;
    int ok = 0;
    if (op[0] == '*') ok = _CHECKED_OP_UMULT(res, first, second, range_ulong);
    else if (op[0] == '/') ok = _CHECKED_OP_UDIV(res, first, second);
    else if (op[0] == '+') ok = _CHECKED_OP_UADD(res, first, second, range_ulong);
    else if (op[0] == '-') ok = _CHECKED_OP_USUB(res, first, second);
    if (!ok) return 0;
    if (as[0] == '=') *lval = temp_res;
    else if (as[0] == '+') return _CHECKED_OP_UADD(lval, *lval, temp_res, range_ulong);
    else if (as[0] == '-') return _CHECKED_OP_USUB(lval, *lval, temp_res);
    else if (as[0] == '*') return _CHECKED_OP_UMULT(lval, *lval, temp_res, range_ulong);
    else if (as[0] == '/') return _CHECKED_OP_UDIV(lval, *lval, temp_res);
    return 1;
}
#if HAS_LONG_LONG
static inline int checked_op_handler_llong(long long *lval, const char* as, intmax_t first, const char* op, intmax_t second) {
    long long temp_res;
    long long *res = &temp_res;
    int ok = 0;
    if (op[0] == '*') ok = _CHECKED_OP_MULT(res, first, second, range_llong);
    else if (op[0] == '/') ok = _CHECKED_OP_DIV(res, first, second, range_llong);
    else if (op[0] == '+') ok = _CHECKED_OP_ADD(res, first, second, range_llong);
    else if (op[0] == '-') ok = _CHECKED_OP_SUB(res, first, second, range_llong);
    if (!ok) return 0;
    if (as[0] == '=') *lval = temp_res;
    else if (as[0] == '+') return _CHECKED_OP_ADD(lval, *lval, temp_res, range_llong);
    else if (as[0] == '-') return _CHECKED_OP_SUB(lval, *lval, temp_res, range_llong);
    else if (as[0] == '*') return _CHECKED_OP_MULT(lval, *lval, temp_res, range_llong);
    else if (as[0] == '/') return _CHECKED_OP_DIV(lval, *lval, temp_res, range_llong);
    return 1;
}
static inline int checked_op_handler_ullong(unsigned long long *lval, const char* as, uintmax_t first, const char* op, uintmax_t second) {
    unsigned long long temp_res;
    unsigned long long *res = &temp_res;
    int ok = 0;
    if (op[0] == '*') ok = _CHECKED_OP_UMULT(res, first, second, range_ullong);
    else if (op[0] == '/') ok = _CHECKED_OP_UDIV(res, first, second);
    else if (op[0] == '+') ok = _CHECKED_OP_UADD(res, first, second, range_ullong);
    else if (op[0] == '-') ok = _CHECKED_OP_USUB(res, first, second);
    if (!ok) return 0;
    if (as[0] == '=') *lval = temp_res;
    else if (as[0] == '+') return _CHECKED_OP_UADD(lval, *lval, temp_res, range_ullong);
    else if (as[0] == '-') return _CHECKED_OP_USUB(lval, *lval, temp_res);
    else if (as[0] == '*') return _CHECKED_OP_UMULT(lval, *lval, temp_res, range_ullong);
    else if (as[0] == '/') return _CHECKED_OP_UDIV(lval, *lval, temp_res);
    return 1;
}
#endif

/**
 * @brief 연결리스트가 비었는지 확인합니다.
 * @param list LinkedList 포인터
 * @return 비었으면 true, 아니면 false
 */
bool user_is_empty(LinkedList* list) {
    return list->size == 0;
}

/**
 * @brief 스레드 안전하게 printf를 수행합니다.
 * @param format printf 포맷 문자열
 * @param ... 가변 인자
 */
void user_safe_printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    pthread_mutex_lock(&print_mutex);
    vprintf(format, args);
    pthread_mutex_unlock(&print_mutex);
    va_end(args);
}

/**
 * @brief 연결리스트를 생성합니다.
 * @return LinkedList 포인터
 */
LinkedList* user_create_linkedlist(void) {
    LinkedList* list = (LinkedList*)malloc(sizeof(LinkedList));
    list->head = NULL;
    list->tail = NULL;
    list->size = 0;
    return list;
}

/**
 * @brief 안전하게 int 곱셈을 수행하며 오버플로우를 체크합니다.
 * @param res 결과를 저장할 포인터
 * @param a 피연산자1
 * @param b 피연산자2
 * @return 오버플로우 발생 시 0, 정상 계산 시 1
 */
static int checked_mult(int *res, int a, int b) {
    return SAFE_OP(*res, =, a, *, b);
}

/**
 * @brief 테스트 케이스를 실행하고 결과를 출력합니다.
 */
static void run_standard_tests(void) {
    int a = 100000, b = 100000, res;
    user_safe_printf("[테스트] 곱셈 오버플로우 체크: %d * %d\n", a, b);
    if (!checked_mult(&res, a, b)) {
        user_safe_printf("오버플로우 발생!\n");
    } else {
        user_safe_printf("정상 결과: %d\n", res);
    }
}

/**
 * @brief 벤치마크용 함수. 주어진 함수 포인터를 반복 호출합니다.
 * @param f int를 받아 int를 반환하는 함수 포인터
 * @return 반복 종료 후 값
 */
static int bench(int (* volatile f)(int)) {
    int sum = 0;
    for (int i = 0; i < 100000; ++i)
        sum += f(i);
    return sum;
}
/**
 * @brief 벤치마크용 함수들
 * 
 * (1) checked_mult 사용
 * (2) SAFE_OP 매크로 직접 사용
 * (3) 수동 오버플로우 체크 (manual)
 * (4) 아무 체크 없이 곱셈 (unsafe)
 */
// (1) checked_mult 사용
static int bench_checked_mult(int x) {
    int res;
    checked_mult(&res, x, 100);
    return res;
}
// (2) SAFE_OP 직접 사용
static int bench_safe_op(int x) {
    int res;
    SAFE_OP(res, =, x, *, 100);
    return res;
}
// (3) 수동 오버플로우 체크 (manual)
static int bench_manual(int x) {
    int res;
    if (x > 0 && 100 > INT_MAX / x) return 0;
    if (x < 0 && 100 < INT_MIN / x) return 0;
    res = x * 100;
    return res;
}
// (4) 아무 체크 없이 곱셈 (unsafe)
static int bench_clean(int x) {
    return x * 100;
}

/**
 * @brief 표준 테스트 및 벤치마크를 실행하고, show_help 플래그를 반환합니다.
 * @param argc 인자 개수
 * @param argv 인자 배열
 * @return show_help 플래그
 */
static int run_all__(int argc, char const **argv) {
    run_standard_tests();

    int show_help = 0;
    int do_bench = 0;
    char bench_mode = 0;

    // 인자 파싱
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "v") == 0) show_help = 1;
        if (strcmp(argv[i], "f") == 0) { do_bench = 1; bench_mode = 'f'; }
        if (strcmp(argv[i], "s") == 0) { do_bench = 1; bench_mode = 's'; }
        if (strcmp(argv[i], "h") == 0) { do_bench = 1; bench_mode = 'h'; }
        if (strcmp(argv[i], "c") == 0) { do_bench = 1; bench_mode = 'c'; }
        if (strcmp(argv[i], "llm") == 0) { do_bench = 1; bench_mode = 'l'; }
    }

    if (do_bench) {
        int result = 0;
        switch (bench_mode) {
            case 'f':
                PRLOG_I("bench", "checked_mult 함수 사용");
                result = bench(bench_checked_mult);
                break;
            case 's':
                PRLOG_I("bench", "SAFE_OP 매크로 직접 사용");
                result = bench(bench_safe_op);
                break;
            case 'h':
                PRLOG_I("bench", "수동 오버플로우 체크");
                result = bench(bench_manual);
                break;
            case 'c':
                PRLOG_I("bench", "아무 체크 없이 곱셈 (unsafe)");
                result = bench(bench_clean);
                break;
        }
        PRLOG_I("bench", "bench 결과: %d", result);
    }

    return show_help;
}

/**
 * @brief 연결리스트에 데이터를 push합니다.
 * @param list LinkedList 포인터
 * @param data 추가할 데이터 포인터
 */
void user_push(LinkedList* list, void* data) {
    Node* new_node = (Node*)malloc(sizeof(Node));
    new_node->data = data;
    new_node->next = NULL;
    if (user_is_empty(list)) {
        list->head = list->tail = new_node;
    } else {
        list->tail->next = new_node;
        list->tail = new_node;
    }
    list->size++;
}

/**
 * @brief 연결리스트에서 데이터를 pop합니다.
 * @param list LinkedList 포인터
 * @return pop된 데이터 포인터
 */
void* user_pop(LinkedList* list) {
    if (user_is_empty(list)) {
        user_safe_printf("빈 리스트에서 pop 시도\n");
        return NULL;
    }
    Node* temp = list->head;
    void* data = temp->data;
    list->head = list->head->next;
    if (list->head == NULL) list->tail = NULL;
    free(temp);
    list->size--;
    return data;
}

/**
 * @brief 연결리스트를 파괴합니다.
 * @param list LinkedList 포인터
 */
void user_destroy_linkedlist(LinkedList* list) {
    while (!user_is_empty(list)) {
        user_pop(list);
    }
    free(list);
}

/**
 * @brief 세마포어를 동적으로 초기화합니다.
 * @param value 초기값
 * @return 세마포어 포인터
 */
sem_t* user_init_semaphore(int value) {
    sem_t* sem = (sem_t*)malloc(sizeof(sem_t));
    if (sem_init(sem, 0, value) != 0) {
        perror("세마포어 초기화 실패");
        free(sem);
        return NULL;
    }
    return sem;
}

/**
 * @brief 뮤텍스를 동적으로 초기화합니다.
 * @return 뮤텍스 포인터
 */
pthread_mutex_t* user_init_mutex() {
    pthread_mutex_t* mutex = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
    if (pthread_mutex_init(mutex, NULL) != 0) {
        user_safe_printf("뮤텍스 초기화 실패\n");
        free(mutex);
        return NULL;
    }
    return mutex;
}

/**
 * @brief 세마포어 기반 스레드 작업 함수
 * @param arg 세마포어 포인터
 * @return NULL
 */
void* user_semaphore_thread(void* arg) {
    sem_t* semaphore = (sem_t*)arg;
    user_safe_printf("세마포어 대기\n");
    sem_wait(semaphore);
    user_safe_printf("세마포어 획득\n");
    sleep(1);
    sem_post(semaphore);
    user_safe_printf("세마포어 해제\n");
    return NULL;
}

/**
 * @brief 뮤텍스 기반 스레드 작업 함수
 * @param arg 뮤텍스 포인터
 * @return NULL
 */
void* user_mutex_thread(void* arg) {
    pthread_mutex_t* mutex = (pthread_mutex_t*)arg;
    user_safe_printf("뮤텍스 대기\n");
    pthread_mutex_lock(mutex);
    user_safe_printf("뮤텍스 획득\n");
    sleep(1);
    pthread_mutex_unlock(mutex);
    user_safe_printf("뮤텍스 해제\n");
    return NULL;
}

/**
 * @brief 멀티스레드 작업을 실행합니다.
 * @param num_threads 스레드 개수
 * @param use_semaphore 1이면 세마포어, 0이면 뮤텍스
 */
void user_run_multithreading(int num_threads, int use_semaphore) {
    user_safe_printf("멀티스레드 실행 (쓰레드 수: %d, 동기화: %s)\n",
        num_threads, use_semaphore ? "세마포어" : "뮤텍스");
    pthread_t* threads = (pthread_t*)malloc(num_threads * sizeof(pthread_t));
    if (use_semaphore) {
        sem_t* sem = user_init_semaphore(1);
        for (int i = 0; i < num_threads; i++)
            pthread_create(&threads[i], NULL, user_semaphore_thread, sem);
        for (int i = 0; i < num_threads; i++)
            pthread_join(threads[i], NULL);
        sem_destroy(sem);
        free(sem);
    } else {
        pthread_mutex_t* mutex = user_init_mutex();
        for (int i = 0; i < num_threads; i++)
            pthread_create(&threads[i], NULL, user_mutex_thread, mutex);
        for (int i = 0; i < num_threads; i++)
            pthread_join(threads[i], NULL);
        pthread_mutex_destroy(mutex);
        free(mutex);
    }
    free(threads);
    user_safe_printf("멀티스레드 종료\n");
}

/**
 * @brief 단일 프로세스를 생성하여 함수 실행
 * @param func 실행할 함수 포인터
 */
void user_create_single_process(void (*func)()) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("프로세스 생성 실패");
    } else if (pid == 0) {
        func();
        exit(EXIT_SUCCESS);
    } else {
        wait(NULL);
    }
}

/**
 * @brief 여러 프로세스를 생성하여 각각 함수 실행
 * @param num_processes 프로세스 개수
 * @param funcs 함수 포인터 배열
 */
void user_create_multi_processes(int num_processes, void (**funcs)()) {
    for (int i = 0; i < num_processes; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("프로세스 생성 실패");
        } else if (pid == 0) {
            funcs[i]();
            exit(EXIT_SUCCESS);
        }
    }
    for (int i = 0; i < num_processes; i++) {
        wait(NULL);
    }
}

// 데모용 함수
void child_func() {
    user_safe_printf("자식 프로세스에서 실행됨 (PID: %d)\n", getpid());
}
void process_func_1() {
    user_safe_printf("멀티프로세스 1 (PID: %d)\n", getpid());
}
void process_func_2() {
    user_safe_printf("멀티프로세스 2 (PID: %d)\n", getpid());
}

void run_llm_demo(void) {
    llm_model_t* model = llm_model_load("llama-2-7b.gguf");
    llm_context_params_t ctx_params = { .n_ctx = 512, .n_threads = 4, .use_gpu = false };
    llm_context_t* ctx = llm_context_create(model, ctx_params);

    llm_sampling_params_t sampling = { .temperature = 0.8f, .top_k = 40, .top_p = 0.95f };
    char output[2048];
    llm_generate(ctx, "안전 산술연산 엔진의 장점을 한 문장으로 요약해줘.", output, sizeof(output), sampling);
    printf("LLM 응답: %s\n", output);

    llm_context_free(ctx);
    llm_model_free(model);
}

// ====== 데모 실행 함수 ======
void run_user_kernel_demo(void) {
    user_safe_printf("\n[유저레벨 커널 엔진 데모]\n");

    // 1. 멀티스레드(세마포어)
    user_run_multithreading(2, 1);

    // 2. 멀티스레드(뮤텍스)
    user_run_multithreading(2, 0);

    // 3. 단일 프로세스
    user_safe_printf("단일 프로세스 생성 예시\n");
    user_create_single_process(child_func);

    // 4. 다중 프로세스
    user_safe_printf("다중 프로세스 생성 예시\n");
    void (*funcs[2])() = {process_func_1, process_func_2};
    user_create_multi_processes(2, funcs);

    // 5. 연결리스트
    user_safe_printf("연결리스트 예시\n");
    LinkedList* list = user_create_linkedlist();
    int a = 10, b = 20, c = 30;
    user_push(list, &a);
    user_push(list, &b);
    user_push(list, &c);
    while (!user_is_empty(list)) {
        int* val = (int*)user_pop(list);
        user_safe_printf("pop: %d\n", *val);
    }
    user_destroy_linkedlist(list);

    // 6. 벤치마크
    printf("\n **********************************\n");
    user_safe_printf("[핸들 기반 메모리 벤치마크]\n");
    run_handle_bench();
    destroy_all_mem_handles();

    user_safe_printf("[데모 종료]\n");
}

/**
 * @brief 임계영역 보호(뮤텍스) 작업 스레드 함수
 * @param arg SharedCounter 포인터
 * @return NULL
 */
void* critical_section_worker(void* arg) {
    SharedCounter* counter = (SharedCounter*)arg;
    pthread_mutex_lock(&counter->mutex);
    user_safe_printf("[뮤텍스] 임계영역 진입, count=%d\n", counter->count);
    counter->count++;
    sleep(1);
    pthread_mutex_unlock(&counter->mutex);
    return NULL;
}

/**
 * @brief 리소스 제한(세마포어) 작업 스레드 함수
 * @param arg SharedCounter 포인터
 * @return NULL
 */
void* resource_section_worker(void* arg) {
    SharedCounter* counter = (SharedCounter*)arg;
    sem_wait(&counter->semaphore);
    user_safe_printf("[세마포어] 리소스 사용, count=%d\n", counter->count);
    counter->count++;
    sleep(1);
    sem_post(&counter->semaphore);
    return NULL;
}


/**
 * @brief TaskManager에 따라 적절한 동기화 방식으로 멀티스레드 작업을 실행합니다.
 * @param manager TaskManager 포인터
 */
void run_task_manager(TaskManager* manager) {
    pthread_t* threads = malloc(sizeof(pthread_t) * manager->num_threads);
    SharedCounter* counter = (SharedCounter*)manager->shared_resource;

    if (manager->type == TASK_MUTEX_CRITICAL) {
        user_safe_printf("\n[TaskManager] 임계영역 보호(뮤텍스) 작업 시작\n");
        pthread_mutex_init(&counter->mutex, NULL);
        counter->count = 0;
        for (int i = 0; i < manager->num_threads; ++i)
            pthread_create(&threads[i], NULL, critical_section_worker, counter);
        for (int i = 0; i < manager->num_threads; ++i)
            pthread_join(threads[i], NULL);
        pthread_mutex_destroy(&counter->mutex);
        user_safe_printf("[TaskManager] 임계영역 보호(뮤텍스) 작업 종료, 최종 count=%d\n", counter->count);
    } else if (manager->type == TASK_SEMAPHORE_RESOURCE) {
        user_safe_printf("\n[TaskManager] 리소스 제한(세마포어) 작업 시작\n");
        sem_init(&counter->semaphore, 0, 2); // 동시에 2개만 진입 허용
        counter->count = 0;
        for (int i = 0; i < manager->num_threads; ++i)
            pthread_create(&threads[i], NULL, resource_section_worker, counter);
        for (int i = 0; i < manager->num_threads; ++i)
            pthread_join(threads[i], NULL);
        sem_destroy(&counter->semaphore);
        user_safe_printf("[TaskManager] 리소스 제한(세마포어) 작업 종료, 최종 count=%d\n", counter->count);
    } else {
        user_safe_printf("[TaskManager] 알 수 없는 작업 유형\n");
    }
    free(threads);
}

/**
 * @brief TaskManager 데모를 실행합니다.
 */
 void run_task_manager_demo(void) {
    SharedCounter counter1, counter2;

    // 1. 임계영역 보호(뮤텍스)
    TaskManager tm_mutex = {
        .type = TASK_MUTEX_CRITICAL,
        .num_threads = 4,
        .shared_resource = &counter1
    };
    run_task_manager(&tm_mutex);

    // 2. 리소스 제한(세마포어)
    TaskManager tm_sema = {
        .type = TASK_SEMAPHORE_RESOURCE,
        .num_threads = 6,
        .shared_resource = &counter2
    };
    run_task_manager(&tm_sema);

    // ====== main내 조건 분기에서 호출 ======
    /*
    if (show_help) {
        ...
        PRLOG_I("demo", "TaskManager 상황별 동기화 데모");
        run_task_manager_demo();
    }
    */
}


// ====== show_help 분기에서 호출 ======
/**
 * @brief 커맨드 라인 인자 파싱 구조체
 */
typedef struct {
    bool run_mode;
    bool show_help;
    char bench_mode;
} CmdArgs;

/**
 * @brief 커맨드 라인 인자 파싱 함수
 */
static CmdArgs parse_args(int argc, char const **argv) {
    CmdArgs args = {0};
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "run") == 0) args.run_mode = true;
        else if (strcmp(argv[i], "v") == 0) args.show_help = true;
        else if (strcmp(argv[i], "f") == 0) args.bench_mode = 'f';
        else if (strcmp(argv[i], "s") == 0) args.bench_mode = 's';
        else if (strcmp(argv[i], "h") == 0) args.bench_mode = 'h';
        else if (strcmp(argv[i], "c") == 0) args.bench_mode = 'c';
    }
    return args;
}

/**
 * @brief 벤치마크 실행 함수
 */
static void run_benchmark(char bench_mode) {
    int result = 0;
    switch (bench_mode) {
        case 'f':
            PRLOG_I("bench", "checked_mult 함수 사용");
            result = bench(bench_checked_mult);
            break;
        case 's':
            PRLOG_I("bench", "SAFE_OP 매크로 직접 사용");
            result = bench(bench_safe_op);
            break;
        case 'h':
            PRLOG_I("bench", "수동 오버플로우 체크");
            result = bench(bench_manual);
            break;
        case 'c':
            PRLOG_I("bench", "아무 체크 없이 곱셈 (unsafe)");
            result = bench(bench_clean);
            break;
        default:
            PRLOG_E("bench", "벤치마크 모드 인자가 없습니다.");
            return;
    }
    PRLOG_I("bench", "bench 결과: %d", result);
}

/**
 * @brief 시뮬레이션(데모) 실행 함수
 */
static void run_full_demo(void) {
    PRLOG_I("demo", "본격 시뮬레이션 모드 시작");

    // 유저레벨 커널 엔진 데모
    run_user_kernel_demo();

    // TaskManager 상황별 동기화 데모
    PRLOG_I("demo", "TaskManager 상황별 동기화 데모");
    run_task_manager_demo();

    // 스마트 포인터 데모
    PRLOG_I("demo", "스마트 포인터 데모");
    SmartPtr sp1 = CREATE_SMART_PTR(int, 123);
    safe_kernel_printf("SmartPtr 값: %d\n", *(int*)sp1.ptr);
    retain(&sp1);
    safe_kernel_printf("retain 후 ref_count: %d\n", *sp1.ref_count);
    release(&sp1);
    safe_kernel_printf("release 후 ref_count: %d\n", *sp1.ref_count);
    release(&sp1);

    // 네트워크 정보 데모
    PRLOG_I("demo", "로컬 네트워크 정보 데모");
    NetworkInfo netinfo = get_local_network_info();
    safe_kernel_printf("Local IP: %s, Family: %d\n", netinfo.ip, netinfo.family);

    // 커널 스레드 생성/조인 데모
    PRLOG_I("demo", "커널 스레드 생성/조인 데모");
    pthread_t threads[NUM_THREADS];
    int thread_nums[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; ++i) {
        thread_nums[i] = i + 1;
        kernel_create_thread(&threads[i], thread_function, &thread_nums[i]);
    }
    for (int i = 0; i < NUM_THREADS; ++i) {
        kernel_join_thread(threads[i]);
    }

    // 소켓 통신 데모 (로컬 파이프)
    PRLOG_I("demo", "커널 소켓 통신 데모");
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
        perror("socketpair");
    } else {
        pid_t pid = fork();
        if (pid == 0) {
            // 자식: 메시지 읽고 응답
            close(sv[0]);
            char buf[BUF_SIZE];
            ssize_t n = read(sv[1], buf, BUF_SIZE - 1);
            buf[n] = '\0';
            safe_kernel_printf("Child received: %s\n", buf);
            const char *reply = "pong";
            write(sv[1], reply, strlen(reply));
            close(sv[1]);
            exit(0);
        } else {
            // 부모: 메시지 보내고 응답 받기
            close(sv[1]);
            char response[BUF_SIZE];
            kernel_socket_communication(sv[0], "ping", response, BUF_SIZE);
            safe_kernel_printf("Parent received: %s\n", response);
            close(sv[0]);
            kernel_wait_for_process(pid);
        }
    }

    PRLOG_I("demo", "시뮬레이션 종료");
}

/**
 * @brief 도움말 및 벤치마크 안내 출력
 */
static void print_help(void) {
    PRLOG_I("\nUsage: ./safe_arithmetic_ops [ run|v|f|s|h|c|llm ]");
    PRLOG_I("  run : 전체 커널/동기화/스마트포인터/네트워크 데모 실행");
    PRLOG_I("  v   : 표준 테스트 및 유저레벨 커널 데모(자세히)");
    PRLOG_I("  f   : checked_mult 함수 벤치마크");
    PRLOG_I("  s   : SAFE_OP 매크로 벤치마크");
    PRLOG_I("  h   : 수동 오버플로우 체크 벤치마크");
    PRLOG_I("  c   : 아무 체크 없는 곱셈 벤치마크");
    PRLOG_I("  llm : LLM 모델 로드 및 간단한 질의 실행 (예시)");
    PRLOG_I("  --help, -h : 도움말 출력");

    PRLOG_I("\n예시: ./safe_arithmetic_ops argc");
}

/**
 * @brief 메인 함수
 */
int main(int argc, char const **argv) {
#ifdef _DEBUG
    start_log_thread();
    atexit(stop_log_thread);
#endif

    CmdArgs args = parse_args(argc, argv);

    // 도움말 인자 처리
    if (argc > 1 && (
        strcmp(argv[1], "help") == 0 ||
        strcmp(argv[1], "hel") == 0 ||
        strcmp(argv[1], "--help") == 0 ||
        strcmp(argv[1], "-h") == 0
    )) {
        print_help();
        return EXIT_SUCCESS;
    }

    // 인자 유효성 검사
    const char *valid_args[] = {"run", "v", "f", "s", "h", "c", "llm"};
    int is_valid = 0;
    if (argc > 1) {
        for (size_t i = 0; i < sizeof(valid_args)/sizeof(valid_args[0]); ++i) {
            if (strcmp(argv[1], valid_args[i]) == 0) {
                is_valid = 1;
                break;
            }
        }
        if (!is_valid) {
            PRLOG_E("잘못된 인자입니다: %s", argv[1]);
            print_help();
            return EXIT_FAILURE;
        }
    } else {
        PRLOG_E("인자가 없습니다. 기본적으로 표준 테스트 및 벤치마크를 실행합니다.");
        print_help();
        return EXIT_FAILURE;
    }

    // LLM 모드
    if (strcmp(argv[1], "llm") == 0) {
        PRLOG_I("[LLM] 시스템 정보:");
        puts(llama_print_system_info());

        const char* model_path = "../models/gpt2-medium-q4_0.gguf";
        struct stat st;
        if (stat(model_path, &st) != 0) {
            PRLOG_E("[LLM] 모델 파일이 존재하지 않습니다: %s", model_path);
            return EXIT_FAILURE;
        }

        llm_model_t* model = llm_model_load(model_path);
        if (!model) {
            PRLOG_E("[LLM] 모델 로드 실패: %s", model_path);
            return EXIT_FAILURE;
        }

        llm_context_params_t ctx_params = { .n_ctx = 512, .n_threads = 4, .use_gpu = false };
        llm_context_t* ctx = llm_context_create(model, ctx_params);

        llm_sampling_params_t sampling = { .temperature = 0.8f, .top_k = 40, .top_p = 0.95f };
        char output[2048];
        llm_generate(ctx, "이 엔진의 안전 산술연산 기능을 한 문장으로 요약해줘.", output, sizeof(output), sampling);
        printf("[LLM 응답] %s\n", output);

        llm_context_free(ctx);
        llm_model_free(model);

        PRLOG_I("[LLM] 질의 완료");
        return EXIT_SUCCESS;
    }

    // 전체 데모 실행
    if (args.run_mode) {
        run_full_demo();
        return EXIT_SUCCESS;
    }

    // 표준 테스트 및 벤치마크 (수동/내장 오버플로우 체크)
    for (int use_gcc = 0; use_gcc <= 1; ++use_gcc) {
#if defined(__GNUC__) && __GNUC__ >= 5
        g_use_gcc_builtins = use_gcc;
        PRLOG_I(use_gcc ? "\n--- GCC built-in overflow checks ---" : "--- Manual overflow checks ---");
        int show_help = run_all__(argc, argv);
#else
        if (use_gcc == 0) {
            g_use_gcc_builtins = 0;
            PRLOG_I("--- Manual overflow checks ---");
            int show_help = run_all__(argc, argv);
        }
#endif
    }

    // 벤치마크 모드
    if (args.bench_mode) {
        run_benchmark(args.bench_mode);
    }

    // 상세 데모 (v 인자)
    if (args.show_help) {
        PRLOG_I("\n[유저레벨 커널 엔진 데모]");
        run_user_kernel_demo();
    } else {
        PRLOG_I("\n[테스트 완료]");
    }

    return EXIT_SUCCESS;
}
