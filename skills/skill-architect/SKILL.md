---
name: skill-architect
description: Audit and architect Claude skills against production-quality criteria — state design, interruption resilience, input gates, token/model tiering, human-in-the-loop design, machine-enforced validation, OKF knowledge output, and marketplace deployment. Use when the user asks to review/audit/improve a skill's design, asks "is this skill well made", wants to design a new non-trivial skill, or mentions skill quality, 스킬 검토, 스킬 설계, 스킬 감사, 스킬 품질. For scaffolding, evals, and description optimization, delegates to the skill-creator skill when available.
---

# Skill Architect

스킬을 프로덕션 품질 기준으로 감사(audit)하고 설계하는 스킬이다.
기준은 `ARCHITECTURE_CHECKLIST.md`에 있으며, 실제 대규모 워크플로우
스킬(sast-remediation)을 운영하며 도출된 것이다.

## skill-creator와의 관계

- **skill-creator** (있으면 위임): 스캐폴딩, 테스트 프롬프트, 평가
  실행·벤치마크, description 트리거 최적화
- **skill-architect** (이 스킬): 아키텍처 품질 — 무엇을 파일로 남기고,
  끊기면 어떻게 되고, 누가 규칙을 강제하고, 토큰을 어디서 아끼는지

신규 스킬을 만들 때는 체크리스트를 설계 단계에 선반영한 뒤
skill-creator로 스캐폴딩·평가를 진행한다. skill-creator가 없으면 직접
수행한다.

## 감사 절차 (기존 스킬 검토 요청 시)

1. 대상 스킬 로드: SKILL.md와 동봉 파일 전체를 읽는다. 마켓플레이스
   구조(plugin.json, agents/)가 있으면 함께 본다.
2. 스킬의 성격을 먼저 판정한다: 단순 변환형(문서 생성, 포맷팅) /
   워크플로우형(다단계, 상태 보유) / 지식형(참조 문서 중심).
   성격에 따라 체크리스트 항목의 해당 여부가 달라진다 — 단순 변환형에
   게이트나 재개 절차를 요구하지 않는다.
3. `ARCHITECTURE_CHECKLIST.md`의 10개 범주를 항목별로 판정한다:
   **적용 / 부분 / 미적용 / 해당없음** + 한 줄 근거. 추측하지 말고
   파일에서 확인한 사실만 근거로 쓴다.
4. 리포트를 표로 제시하고, 개선을 임팩트 순으로 3~5개 제안한다.
   각 제안에 예상 효과(토큰, 안정성, 사용성)를 명시한다.
5. 사용자가 승인한 항목만 적용한다. 적용 후 스킬이 플러그인이면
   버전을 올리고 변경 요약을 남긴다.

## 설계 절차 (신규 스킬 요청 시)

1. 스킬 성격 판정(위 2번과 동일) 후, 해당 범주만 골라 설계 질문을
   한 번에 최대 3개씩 확인한다: 상태를 파일로 남길 것인가, 끊기면
   어디서 재개하는가, 무엇을 기계로 검증하는가, 사람 개입 지점은
   어디인가.
2. 결정 사항을 설계 요약으로 확인받은 뒤 skill-creator(있으면)로
   스캐폴딩과 평가를 진행한다.
3. 완성 후 본 스킬의 감사 절차를 1회 돌려 자체 점검한다.

## 보고 형식

감사 리포트는 다음 표 + 개선 제안으로 구성한다.

| 범주 | 판정 | 근거 |
|---|---|---|
| 1. 트리거 설계 | 적용 | description에 영/한 키워드, 오발동 제외 조건 명시 |
| ... | | |

판정 요약: 적용 n / 부분 n / 미적용 n / 해당없음 n
