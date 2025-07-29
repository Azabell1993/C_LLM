#ifndef SAFE_ARITHMETIC_OPS_H
#define SAFE_ARITHMETIC_OPS_H

#include <stdio.h>
#include <limits.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <netinet/in.h>

#define BUF_SIZE 100
#define NUM_THREADS 3
#define MAX_STRING_SIZE 100

/**
 * @struct SmartPtr
 * @brief 스마트 포인터 구조체
 *
 * 이 구조체는 포인터와 참조 카운트, 뮤텍스를 관리합니다.
 */
typedef struct SmartPtr {
    void *ptr;                ///< 실제 메모리를 가리킴
    int *ref_count;           ///< 참조 카운트
    pthread_mutex_t *mutex;   ///< 뮤텍스 보호
} SmartPtr;

/**
 * @brief 네트워크 정보를 저장하는 구조체
 */
typedef struct {
    char ip[INET_ADDRSTRLEN];  ///< IPv4 주소
    sa_family_t family;        ///< 주소 패밀리 (AF_INET 등)
} NetworkInfo;

/**
 * @struct Node
 * @brief 연결 리스트의 노드를 정의하는 구조체
 * 
 * 각 노드는 데이터를 저장하고, 다음 노드를 가리킵니다.
 */
typedef struct Node {
    void* data;           ///< 데이터를 가리키는 포인터 */
    struct Node* next;    ///< 다음 노드를 가리키는 포인터 */
} Node;

/**
 * @struct LinkedList
 * @brief 연결 리스트를 정의하는 구조체
 * 
 * 연결 리스트의 헤드, 테일, 크기를 포함합니다.
 */
typedef struct LinkedList {
    Node* head;           ///< 연결 리스트의 첫 번째 노드를 가리키는 포인터 */
    Node* tail;           ///< 연결 리스트의 마지막 노드를 가리키는 포인터 */
    int size;             ///< 연결 리스트의 크기 */
} LinkedList;

/**
 * @brief TaskManager의 작업 유형
 */
typedef enum {
    TASK_MUTEX_CRITICAL,      // 뮤텍스가 적합한 임계영역 보호 작업
    TASK_SEMAPHORE_RESOURCE,  // 세마포어가 적합한 리소스 제한 작업
    TASK_NONE
} TaskType;

/**
 * @brief TaskManager 구조체. 동기화 유형, 스레드 수, 공유자원 포인터를 포함합니다.
 */
typedef struct {
    TaskType type;
    int num_threads;
    void* shared_resource;
    // 추가 필드 가능
} TaskManager;

/**
 * @brief 공유 카운터 구조체. 뮤텍스와 세마포어를 모두 포함합니다.
 */
typedef struct {
    int count;
    pthread_mutex_t mutex;
    sem_t semaphore;
} SharedCounter;
#define BUF_SIZE 100
#define NUM_THREADS 3
#define MAX_STRING_SIZE 100

typedef struct SmartPtr SmartPtr;
#define CREATE_SMART_PTR(type, ...) create_smart_ptr(sizeof(type), __VA_ARGS__)

static void retain(SmartPtr *sp);
static void release(SmartPtr *sp);
static void safe_kernel_printf(const char *format, ...);
static void kernel_errExit(const char *format, ...);
static void kernel_socket_communication(int sock_fd, const char *message, char *response, size_t response_size);
static void kernel_create_thread(pthread_t *thread, void *(*start_routine)(void *), void *arg);
static void* thread_function(void* arg);
static void terminate(bool useExit3);
static void kernel_join_thread(pthread_t thread);
static void kernel_wait_for_process(pid_t pid);
static pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief GGML 백엔드 관련 더미 함수 (컴파일용, 실제 동작 없음)
 */
size_t ggml_backend_reg_count(void) { return 0; }
void *ggml_backend_reg_get(size_t i) { (void)i; return NULL; }
void *ggml_backend_reg_get_proc_address(void *reg, const char *name) { (void)reg; (void)name; return NULL; }
const char *ggml_backend_reg_name(void *reg) { (void)reg; return "dummy"; }


// Example of a specific helper function
/**
 * @brief 안전하게 int 곱셈을 수행하며 오버플로우를 체크합니다.
 * @param res 결과를 저장할 포인터
 * @param a 피연산자1
 * @param b 피연산자2
 * @return 오버플로우 발생 시 0, 정상 계산 시 1
 */
static int checked_mult(int *res, int a, int b);

/**
 * @brief SAFE_OP 매크로의 int 버전. 오버플로우 체크와 연산을 수행합니다.
 * @param lval 결과를 저장할 변수
 * @param as 연산자(=, +=, 등)
 * @param first 첫 번째 피연산자
 * @param op 연산자(+, -, *, /)
 * @param second 두 번째 피연산자
 * @return 오버플로우 발생 시 0, 정상 계산 시 1
 */
static inline int checked_op_handler_int(int *lval, const char* as, intmax_t first, const char* op, intmax_t second);

/**
 * @brief SAFE_OP 매크로의 unsigned int 버전. 오버플로우 체크와 연산을 수행합니다.
 */
static inline int checked_op_handler_uint(unsigned int *lval, const char* as, uintmax_t first, const char* op, uintmax_t second);

/**
 * @brief SAFE_OP 매크로의 long 버전. 오버플로우 체크와 연산을 수행합니다.
 */
static inline int checked_op_handler_long(long *lval, const char* as, intmax_t first, const char* op, intmax_t second);

/**
 * @brief SAFE_OP 매크로의 unsigned long 버전. 오버플로우 체크와 연산을 수행합니다.
 */
static inline int checked_op_handler_ulong(unsigned long *lval, const char* as, uintmax_t first, const char* op, uintmax_t second);

#if defined(__SIZEOF_LONG_LONG__) || (defined(_MSC_VER) && _MSC_VER >= 1400)
#   define HAS_LONG_LONG 1
#else
#   define HAS_LONG_LONG 0
#endif

#if HAS_LONG_LONG
/**
 * @brief SAFE_OP 매크로의 long long 버전. 오버플로우 체크와 연산을 수행합니다.
 */
static inline int checked_op_handler_llong(long long *lval, const char* as, intmax_t first, const char* op, intmax_t second);

/**
 * @brief SAFE_OP 매크로의 unsigned long long 버전. 오버플로우 체크와 연산을 수행합니다.
 */
static inline int checked_op_handler_ullong(unsigned long long *lval, const char* as, uintmax_t first, const char* op, uintmax_t second);
#endif

/**
 * @brief SAFE_OP 매크로. 타입에 따라 적절한 오버플로우 체크 연산을 호출합니다.
 */
#define SAFE_OP(lval, as, first, op, second) \
    _Generic(&(lval), \
        int*: checked_op_handler_int, \
        unsigned int*: checked_op_handler_uint, \
        long*: checked_op_handler_long, \
        unsigned long*: checked_op_handler_ulong, \
        long long*: checked_op_handler_llong, \
        unsigned long long*: checked_op_handler_ullong \
    )(&(lval), #as, first, #op, second)
/**
 * @brief 테스트 케이스를 실행하고 결과를 출력합니다.
 */
static void run_standard_tests(void);

/**
 * @brief 벤치마크용 함수. 주어진 함수 포인터를 반복 호출합니다.
 * @param f int를 받아 int를 반환하는 함수 포인터
 * @return 반복 종료 후 값
 */
static int bench(int (* volatile f)(int));

/**
 * @brief 표준 테스트 및 벤치마크를 실행하고, show_help 플래그를 반환합니다.
 * @param argc 인자 개수
 * @param argv 인자 배열
 * @return show_help 플래그
 */
static int run_all__(int argc, char const **argv);

/**
 * @brief 스레드 안전하게 printf를 수행합니다.
 * @param format printf 포맷 문자열
 * @param ... 가변 인자
 */
void user_safe_printf(const char *format, ...);


/**
 * @brief 연결리스트를 생성합니다.
 * @return LinkedList 포인터
 */
LinkedList* user_create_linkedlist(void);

/**
 * @brief 연결리스트에 데이터를 추가합니다.
 * @param list 연결리스트 포인터
 * @param data 추가할 데이터 포인터
 */
typedef struct ggml_backend_feature {
    const char * name;
    const char * value;
} ggml_backend_feature;
typedef ggml_backend_feature * (*ggml_backend_get_features_t)(void *reg);

/**
 * @brief 메모리 핸들을 정의하는 구조체
 * 
 * 이 구조체는 메모리 주소, 크기, 매핑 상태, 쓰기 캐시 매핑 여부, ID 등을 포함합니다.
 */
typedef struct MemHandle {
    void *addr;
    size_t size;
    int mapped;
    int wc_mapping;
    int id;
    LIST_ENTRY(MemHandle) entries;
} MemHandle;

/**
 * @brief 메모리 핸들을 관리하는 연결 리스트 구조체
 * 
 */
typedef struct {
    LIST_HEAD(, MemHandle) head;
    pthread_mutex_t lock;
    int next_id;
} MemHandleList;

/**
 * @brief 메모리 핸들 리스트를 초기화합니다.
 * @return MemHandleList 초기화된 메모리 핸들 리스트
 */
static MemHandleList g_mem_handles = { .lock = PTHREAD_MUTEX_INITIALIZER, .next_id = 1 };

/**
 * @brief 메모리 핸들을 생성합니다.
 * @param size 할당할 메모리 크기
 * @return MemHandle* 생성된 메모리 핸들
 */
MemHandle* create_mem_handle(size_t size) {
    MemHandle *mh = malloc(sizeof(MemHandle));
    mh->addr = malloc(size);
    mh->size = size;
    mh->mapped = 0;
    mh->wc_mapping = 0;
    pthread_mutex_lock(&g_mem_handles.lock);
    mh->id = g_mem_handles.next_id++;
    LIST_INSERT_HEAD(&g_mem_handles.head, mh, entries);
    pthread_mutex_unlock(&g_mem_handles.lock);
    return mh;
}

#define CREATE_SMART_PTR(type, ...) create_smart_ptr(sizeof(type), __VA_ARGS__)

void user_safe_printf(const char *format, ...);

LinkedList* user_create_linkedlist(void);
void user_push(LinkedList* list, void* data);
void* user_pop(LinkedList* list);
void user_destroy_linkedlist(LinkedList* list);
bool user_is_empty(LinkedList* list);

NetworkInfo get_local_network_info(void);

MemHandle* create_mem_handle(size_t size);
void destroy_mem_handle(MemHandle *mh);
int map_mem_handle(MemHandle *mh);
int unmap_mem_handle(MemHandle *mh);
int handle_safe_add(MemHandle *mh, int offset, int value);
int handle_memcpy(MemHandle *dst, MemHandle *src, size_t size);
void destroy_all_mem_handles(void);

void user_run_multithreading(int num_threads, int use_semaphore);
sem_t* user_init_semaphore(int value);
pthread_mutex_t* user_init_mutex(void);

void user_create_single_process(void (*func)());
void user_create_multi_processes(int num_processes, void (**funcs)());

void run_user_kernel_demo(void);
void run_task_manager(TaskManager* manager);
void run_task_manager_demo(void);

const char * llama_print_system_info(void);

SmartPtr create_smart_ptr(size_t size, ...);
void retain(SmartPtr *sp);
void release(SmartPtr *sp);

#endif // SAFE_ARITHMETIC_OPS_H