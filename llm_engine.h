#ifndef LLM_ENGINE_H
#define LLM_ENGINE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct llm_model llm_model_t;
typedef struct llm_context llm_context_t;

typedef struct {
    int32_t n_ctx;
    int32_t n_threads;
    bool use_gpu;
    // ... 기타 옵션 ...
} llm_context_params_t;

typedef struct {
    float temperature;
    int top_k;
    float top_p;
    // ... 기타 샘플링 옵션 ...
} llm_sampling_params_t;

// 모델 로드/해제
llm_model_t* llm_model_load(const char* model_path);
void         llm_model_free(llm_model_t* model);

// 컨텍스트 생성/해제
llm_context_t* llm_context_create(llm_model_t* model, llm_context_params_t params);
void           llm_context_free(llm_context_t* ctx);

// 프롬프트로부터 텍스트 생성
// out_buf는 충분히 커야 하며, 반환값은 생성된 토큰 수
int llm_generate(
    llm_context_t* ctx,
    const char* prompt,
    char* out_buf,
    size_t out_buf_size,
    llm_sampling_params_t sampling
);

// 기타 유틸
const char* llm_engine_version(void);



#ifdef __cplusplus
}
#endif

#endif // LLM_ENGINE_H