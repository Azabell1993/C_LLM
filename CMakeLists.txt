cmake_minimum_required(VERSION 3.10)
project(safe_arithmetic_ops C)

# 컴파일 옵션
set(CMAKE_C_STANDARD 99)
add_compile_definitions(_DEBUG)
add_compile_options(-g -O0 -pthread)

# 인클루드 디렉토리 설정 (필요시)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# 실행 파일 정의
add_executable(safe_arithmetic_ops
    safe_arithmetic_ops.c
    llm_engine.c
)

# POSIX 스레드 라이브러리 링크
target_link_libraries(safe_arithmetic_ops pthread)
