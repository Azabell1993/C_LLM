# safe_arithmetic_ops 엔진
산술 오버플로우 안전성 테스트, 유저레벨 커널 기능 시뮬레이션, 그리고 LLM 기반 간단한 질의응답 기능까지 통합된 멀티목적 시스템 데모입니다.

## 📁 디렉토리 구조
```
workspace/engine/
├── build.sh                    # 자동 빌드 및 실행 스크립트
├── CMakeLists.txt              # CMake 빌드 구성
├── ename.c.inc                 # 내부용 테스트 데이터 (연결 리스트)
├── llm\_engine.c / .h           # LLM 래퍼 및 질의 처리
├── log.h                       # 로그 출력 매크로
├── models/
│   └── gpt2-medium-q4\_0.gguf   # gguf 포맷 LLM 모델
├── safe\_arithmetic\_ops.c       # 메인 진입점 및 모든 데모 로직 포함
└── README.md                   # 현재 문서
```

빌드 후
```
build/
├── output/
│   ├── ERROR.log               # 에러 로그 기록
│   └── INFO.log                # 실행 로그 기록
└── safe\_arithmetic\_ops         # 실행 파일
````

---

## 🛠️ 주요 기능
| 기능                         | 설명 |
|------------------------------|------|
| 오버플로우 체크 연산         | `SAFE_OP`, `checked_mult` 등 |
| 유저레벨 커널 데모           | 스레드, 세마포어, 뮤텍스, fork 등 |
| 스마트 포인터 데모           | 참조 카운트 기반 메모리 해제 |
| LLM 질의 예제                | GPT2 모델 기반 질문 응답 |
| 로그 파일 분리               | `output/INFO.log`, `ERROR.log` 저장 |

---

## 🚀 빌드 및 실행
### 🔧 자동 빌드
```bash
./build.sh run      # 전체 데모 실행
./build.sh v        # 오버플로우 테스트 + 커널 데모
./build.sh llm      # LLM 질문 응답 예제
````

### 🧰 수동 빌드 (옵션)
```bash
mkdir -p build && cd build
cmake ..
make
./safe_arithmetic_ops v
```

---
## 🔎 실행 옵션 요약
| 옵션             | 설명                                 |
| -------------- | ---------------------------------- |
| `run`          | 전체 데모 실행 (커널, 스마트포인터, 네트워크, LLM 등) |
| `v`            | 오버플로우 체크 + 커널 데모 (상세 출력)           |
| `f`            | `checked_mult()` 벤치마크              |
| `s`            | `SAFE_OP` 매크로 벤치마크                 |
| `h`            | 수동 오버플로우 체크 벤치마크                   |
| `c`            | 무방비 연산 (오버플로우 체크 없음)               |
| `llm`          | GPT2 모델 기반 LLM 질의 실행               |
| `--help`, `-h` | 도움말 출력                             |

---

## 🧠 LLM 예제

```bash
./safe_arithmetic_ops llm
```

* 내부 모델: `models/gpt2-medium-q4_0.gguf`
* 프롬프트 예시:

  ```
  이 엔진의 안전 산술연산 기능을 한 문장으로 요약해줘.
  ```
* 예시 출력(현재 미완성):

  ```
  [LLM 응답] 이 엔진의 안전 산술연산 기능을 한 문장으로 요약해줘. ...
  ```

모델이 없을 경우:

```bash
[LLM] 모델 로드 실패: ../models/gpt2-medium-q4_0.gguf
```

---

## 📜 로그 출력

모든 실행 로그는 `build/output/` 디렉토리에 자동 저장됩니다.

| 파일명         | 설명                        |
| ----------- | ------------------------- |
| `INFO.log`  | 일반 실행 정보, 사용법, 데모 진행 내역 등 |
| `ERROR.log` | 에러 메시지, 인자 누락, 모델 로딩 실패 등 |

예시:

**INFO.log**

```
[INFO] (print_help) - Usage: ./safe_arithmetic_ops [ run|v|f|s|h|c|llm ]
[INFO] (run_full_demo) - demo
...
```

**ERROR.log**

```
[ERROR] (main:1366) - 인자가 없습니다. 기본적으로 표준 테스트 및 벤치마크를 실행합니다.
```

---

## 📋 참고 사항

* C99 기반 코드
* POSIX 환경 (Linux/macOS 등)에서 실행 가능
* LLM 예제는 gguf 모델 파일 필요 (현재 GPT2 medium 사용)
* 출력은 `printf`와 `PRLOG_I`, `PRLOG_E` 로 구성되어 로그 수준별 분리

