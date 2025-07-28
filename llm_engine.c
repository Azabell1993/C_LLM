#include "llm_engine.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 내부 구조체 정의 (실제 구현에서는 llama.cpp 구조체와 연결)
struct llm_model { void* handle; };
struct llm_context { void* handle; };

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
    snprintf(out_buf, out_buf_size, "[LLM 응답] %s ...", prompt);
    printf("[LLM] 프롬프트: %s\n", prompt);
    return strlen(out_buf);
}
const char* llm_engine_version(void) {
    return "llm_engine 0.1";
}