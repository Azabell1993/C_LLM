cmake_minimum_required(VERSION 3.10)
project(safe_arithmetic_ops C)

# C 표준 및 컴파일 옵션
set(CMAKE_C_STANDARD 99)
add_compile_definitions(_DEBUG)
add_compile_options(-g -O0 -pthread)

# 인클루드 디렉토리 설정
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# 정적 라이브러리 정의 (공통 모듈만)
add_library(safeops STATIC
    llm_engine.c
)

# 실행 파일 정의
add_executable(safe_arithmetic_ops_exec
    safe_arithmetic_ops.c
)

# 링크 설정
target_link_libraries(safe_arithmetic_ops_exec safeops pthread)
