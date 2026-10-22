# 설계 — security-assessment 스킬

작성 2026-10-14. 계획: `docs/superpowers/plans/2026-10-14-security-assessment.md`.
sast-remediation의 설계 원칙(HOW_IT_WORKS)을 상속한다.

## 디렉터리 (제안)

```text
skills/security-assessment/
  SKILL.md
  toolkit/
    prompts/            00-authorize, 01-scan-source, 02-triage,
                        03-scan-web, 04-scan-infra, 05-manual-verify,
                        06-evidence, 07-resume
    tools/              assess_toolkit.py (표준 라이브러리), adapters/
    schemas/            scope, finding, disposition, evidence ...
    adapters/           도구별 선언(래퍼) — 명령·가용성·비파괴 여부·SARIF 출력
    data/ project/ findings/ evidence/
    docs/               HOW_IT_WORKS, VERSIONING
```

Claude 전용 서브에이전트는 plugins/ 포장에만 둔다(sast-remediation과 동일).

## 1. 인가 게이트 (가장 중요)

sast-remediation의 입력 게이트를 **인가 게이트**로 확장한다. 스코프 파일:

```text
scope:
  targets:        [ {type: repo|web|infra, value, notes}, ... ]  타입 명시 목록
  exclusions:     제외 자산 (서브도메인·경로·호스트)
  window:         점검 허용 기간 {start, end}
  consent:        {authorizer, role, date, reference}  구조화 필드 + 티켓/문서 URL
  intrusiveness:  passive | active-nondestructive | intrusive
```

`validate`가 검사: targets 각 항목의 type enum·value 존재, consent 네 필드
존재와 reference 형식(URL/티켓), window 유효성, intrusiveness enum.
타입별 의미 확인은 다르게 — repo는 경로 접근성, web은 비파괴 프로브 가능성,
infra는 식별자 대조.

- **기계 점검**: 대상 형식, 기간 유효성, 동의 기록 존재, 침습도 enum.
- **의미 확인**(AI): 대상이 실제 접근 가능한지, 제외 자산과 충돌 없는지,
  동의 기록이 대상과 일치하는지 — 근거와 함께 기록.
- `gate`가 기록과 현재 스코프 파일을 재대조. 스코프 바뀌면 승인 자동 무효.
- READY 아니면 어떤 어댑터도 실행 금지(`validate --strict`·실행 양쪽에서).

## 2. 도구 어댑터 인터페이스

각 스캐너는 선언형 어댑터로 래핑한다(코드가 아니라 데이터 + 얇은 실행부):

```text
adapter:
  id:            semgrep | osv | gitleaks | zap-baseline | checkov ...
  category:      sast | sca | secret | dast | iac
  intrusiveness: passive | active-nondestructive | intrusive
  availability:  설치 확인 명령
  command:       실행 명령 템플릿 (대상·출력 치환)
  output:        sarif | json→sarif 정규화기
```

- 혼합 실행: `intrusiveness ≤ active-nondestructive`이고 사용자가 직접 실행을
  명시했을 때만 스킬이 돌린다. 그 외/도구 미설치는 운영자에게 명령을 지시.
- intrusive는 스코프에 건별 인가가 있어야 하고 운영자 실행만.

> 2026-10-22 grill 확정 사항은 저장소 루트 `CONTEXT.md`(용어·관계)와
> `docs/adr/0001-assessment-confirms-remediation-tracks.md`가 정본이다. 아래와
> 어긋나면 그쪽을 따른다: 게이트는 실수 방지+인가 기록(악의적 사용자는 못 막음),
> 스코프 변경은 의미 필드 기준, 판정·확인 단계 두 축, 확인까지만 추적하고 넘긴
> 결함은 재점검으로 해소 판단, 지문+CWE 동일 시에만 묶음, 산출물은 워크북+표지 보고서.

## 3. 상태·판정 (sast-remediation 상속)

- 정본은 파일. findings는 스캐너 출력에서 생성, disposition은 별도 레코드.
- 판정 enum: `confirmed | suspected | false-positive | out-of-scope |
  needs-review`. confirmed/false-positive는 이유 필수(validate 강제).
- 소스 대조: 코드 레벨 결함은 현재 소스에서 위치·fingerprint 확인(기존 로직 재사용).
- 중복/상관: 여러 스캐너가 같은 결함을 내면 묶는다.

## 4. 증적·SARIF 다리

- 증적: 자산, 심각도(CVSS), 재현 절차, 조치 가이드, 스캐너 출처, 판정 근거.
- SARIF 다리: confirmed 코드 레벨 결함을 SARIF로 내보내 sast-remediation의
  입력(`input/`)에 넣는다. 두 스킬의 경계가 SARIF로 깔끔하게 나뉜다.

## 5. validate가 강제하는 것

게이트 미통과 시 실행 거부, 침습도 초과 작업 거부, 스코프 밖 대상 결과 거부,
판정 이유 누락, 증적 필수 필드 누락, SARIF 정규화 실패, 미러 드리프트.

## 열린 설계 포인트

- 어댑터를 데이터(JSON/TOML)로 둘지 파이썬 모듈로 둘지 — 데이터 우선, 정규화만
  코드.
- 웹 대상의 "접근 가능성" 의미 확인을 어디까지 자동화할지(비파괴 프로브 한계).
- CVSS 산정을 스캐너 값 그대로 쓸지 재계산할지.
