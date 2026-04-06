# jarvis_gateway

`jarvis_gateway`는 JARVIS의 사용자 인증/인가를 담당하는 보안 진입 계층이다.

이 모듈은 "누가 요청했는지", "어느 테넌트 소속인지", "세션이 유효한지"를 판단한다.  
AI 추론이나 플래닝 같은 코어 로직은 여기서 처리하지 않는다.

## 역할

- 로그인/로그아웃 처리
- 회원가입 처리 (`email`/`name` 기반)
- Bearer token 발급 및 검증
- 사용자, 테넌트 기반 접근 제어
- 세션 생성/조회/종료
- rate limit 적용
- audit log 기록 및 조회

## 책임 범위

`jarvis_gateway`가 책임지는 것은 보안과 사용자 컨텍스트다.

- 인증 성공 시 사용자 식별자와 tenant 정보를 반환
- 권한이 없는 요청은 초기에 차단
- 요청 흔적을 audit log에 남겨 운영 추적 가능하게 유지
- 세션 상태를 관리해 상위 계층이 신뢰할 수 있는 사용자 상태 제공

## 다른 모듈과의 관계

- `jarvis_controller`는 직접 인증 로직을 구현하지 않고 `jarvis_gateway` 결과를 사용한다.
- `jarvis_contracts`의 공통 모델을 통해 인증 관련 payload를 외부와 주고받는다.
- `jarvis_core`는 보안 정책보다 추론과 데이터 처리에 집중하고, 인증은 gateway 바깥에서 끝난 상태를 전제로 한다.

## 현재 코드 기준 구성

- `src/jarvis_gateway/app.py`
  - FastAPI 앱과 회원가입/인증/세션/사용자/감사 로그 엔드포인트
- `src/jarvis_gateway/auth.py`
  - 토큰 발급/폐기, principal 해석
- `src/jarvis_gateway/db.py`
  - SQLite 기반 저장 및 조회
- `src/jarvis_gateway/models.py`
  - gateway 전용 request/response 모델
- `src/jarvis_gateway/rate_limit.py`
  - 요청 제한 처리

## 설계 원칙

- 인증과 권한 판정은 gateway에서 끝낸다.
- controller나 core에 보안 정책이 중복되지 않도록 한다.
- 보안 이벤트는 가능한 한 gateway에서 일관되게 남긴다.

## Install

```bash
python3.12 -m pip install -r requirements.txt
python3.12 -m pip install -r requirements-dev.txt
```

## Run

```bash
python3.12 -m uvicorn jarvis_gateway.app:app --reload --port 8002
```

## Test

```bash
python3.12 -m pytest
```

## Lint

```bash
ruff check .
```

## 할 일

- 토큰 저장소를 메모리 기반에서 영속 저장 또는 외부 캐시 기반으로 확장
- 테넌트/사용자 단위 접근 정책을 더 세밀한 permission 체계로 고도화
- audit log 조회 필터와 운영용 검색 기능 정리
- 세션 만료, 강제 종료, 디바이스 구분 정책 명확화
- gateway 전용 모델과 `jarvis_contracts` 공통 계약의 경계를 정리
