#include "llm_engine.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define MAX_PROMPT_HISTORY 16

typedef struct {
    char prompts[MAX_PROMPT_HISTORY][512];
    int count;
} llm_prompt_history_t;

static llm_prompt_history_t g_prompt_history = { .count = 0 };

// 내부 구조체 정의 (실제 구현에서는 llama.cpp 구조체와 연결)
struct llm_model { void* handle; };
struct llm_context { void* handle; };

// 모델 정보 조회 함수
const char* llm_model_info(const llm_model_t* model) {
    if (!model) return "[LLM] 모델 정보 없음";
    return "[LLM] 모델 정보: 데모 핸들 (실제 모델 연동 필요)";
}

// 프롬프트 이력 저장 함수
void llm_save_prompt(const char* prompt) {
    if (g_prompt_history.count < MAX_PROMPT_HISTORY) {
        strncpy(g_prompt_history.prompts[g_prompt_history.count], prompt, 511);
        g_prompt_history.prompts[g_prompt_history.count][511] = '\0';
        g_prompt_history.count++;
    }
}

// 프롬프트 이력 출력 함수
void llm_print_prompt_history(void) {
    printf("[LLM] 프롬프트 이력 (%d개):\n", g_prompt_history.count);
    for (int i = 0; i < g_prompt_history.count; ++i) {
        printf("  %d: %s\n", i+1, g_prompt_history.prompts[i]);
    }
}

// 샘플링 파라미터 동적 변경 함수
void llm_set_sampling_params(llm_sampling_params_t* params, float temperature, int top_k, float top_p) {
    if (!params) return;
    params->temperature = temperature;
    params->top_k = top_k;
    params->top_p = top_p;
}

llm_model_t* llm_model_load(const char* model_path) {
    // 실제로는 llama_model_load_from_file 등 호출
    llm_model_t* model = malloc(sizeof(llm_model_t));
    model->handle = NULL; // 실제 핸들 할당
    printf("[LLM] 모델 로드: %s\n", model_path);
    return model;
}
void llm_model_free(llm_model_t* model) {
    printf("[LLM] 모델 해제\n");
    free(model);
}
llm_context_t* llm_context_create(llm_model_t* model, llm_context_params_t params) {
    llm_context_t* ctx = malloc(sizeof(llm_context_t));
    ctx->handle = NULL; // 실제 핸들 할당
    printf("[LLM] 컨텍스트 생성 (n_ctx=%d, n_threads=%d)\n", params.n_ctx, params.n_threads);
    return ctx;
}
void llm_context_free(llm_context_t* ctx) {
    printf("[LLM] 컨텍스트 해제\n");
    free(ctx);
}
int llm_generate(llm_context_t* ctx, const char* prompt, char* out_buf, size_t out_buf_size, llm_sampling_params_t sampling) {
    // 실제로는 llama_decode 등 호출
    size_t n = 0;
    llm_save_prompt(prompt);
    n += snprintf(out_buf + n, out_buf_size - n, "[LLM 분석]\n");
    n += snprintf(out_buf + n, out_buf_size - n, "- 프롬프트: %s\n", prompt);
    n += snprintf(out_buf + n, out_buf_size - n, "- 프롬프트 길이: %zu\n", strlen(prompt));
    n += snprintf(out_buf + n, out_buf_size - n, "- 출력 버퍼 크기: %zu\n", out_buf_size);
    n += snprintf(out_buf + n, out_buf_size - n, "- 샘플링 파라미터: temperature=%.2f, top_k=%d, top_p=%.2f\n", sampling.temperature, sampling.top_k, sampling.top_p);
    n += snprintf(out_buf + n, out_buf_size - n, "- 모델 핸들: %p\n", ctx ? ctx->handle : NULL);
    n += snprintf(out_buf + n, out_buf_size - n, "- 모델 정보: %s\n", llm_model_info(ctx ? (llm_model_t*)ctx->handle : NULL));
    if (!ctx || !ctx->handle) {
        n += snprintf(out_buf + n, out_buf_size - n, "[경고] LLM 컨텍스트 또는 모델 핸들이 NULL입니다. 실제 추론이 동작하지 않습니다.\n");
    } else {
        n += snprintf(out_buf + n, out_buf_size - n, "[정보] 실제 모델 추론 결과는 여기에 출력되어야 합니다.\n");
    }
    n += snprintf(out_buf + n, out_buf_size - n, "[LLM 응답] (데모) %s ...\n", prompt);
    printf("[LLM] 프롬프트: %s\n", prompt);
    return n;
}
const char* llm_engine_version(void) {
    return "llm_engine 0.1";
}