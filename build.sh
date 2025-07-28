#!/bin/bash

set -e  # 에러 발생 시 즉시 종료

BUILD_DIR="build"
EXECUTABLE="safe_arithmetic_ops"

echo "[INFO] 빌드 시작"

# 기존 build 디렉토리 삭제
if [ -d "$BUILD_DIR" ]; then
    echo "[INFO] 기존 빌드 디렉토리 삭제 중: $BUILD_DIR"
    rm -rf "$BUILD_DIR"
fi

# 빌드 디렉토리 생성 및 이동
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# CMake 구성
echo "[INFO] CMake 구성 중..."
cmake ..

# Make 빌드
echo "[INFO] Make 빌드 중..."
make

# 실행
echo "[INFO] 실행 파일 실행 중..."
./$EXECUTABLE "$@"
