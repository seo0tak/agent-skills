# agent-skills — security-assessment 도메인 언어

`security-assessment` 스킬(인가 기반 보안 점검 오케스트레이터)의 도메인
용어를 정의한다. 계획·설계는 `docs/superpowers/plans|specs/2026-10-14-*`.

## Language

**Authorization gate (인가 게이트)**:
점검 실행 전에 사용자가 선언한 점검 범위를 강제하고 그 인가 주장을 증적에
남기는 관문. _Avoid_: 권한 검사, 접근 제어.

**Scope (스코프)**:
이번 점검에서 인가된 대상·제외·기간·동의·침습도를 담은 선언. 정본은 파일.
_Avoid_: 범위(일반어와 섞일 때).

**Target (대상)**:
점검 대상 하나. `{type: repo|web|infra, value, notes}`로 타입을 명시한다.
_Avoid_: 호스트, 자산(제외 자산과 섞일 때).

**Consent record (동의 기록)**:
소유자가 점검을 인가했다는 주장의 기록. `{authorizer, role, date, reference}`.
_Avoid_: 승인(게이트 통과 상태인 approval과 섞일 때).

**Finding (검출)**:
스캐너가 보고한 잠재 결함 하나. 판정 전에는 사실이 아니라 주장이다.
_Avoid_: 취약점(확인 전에 쓸 때).

**Disposition (판정)**:
검출이 실제 결함인지에 대한 결론. `confirmed | suspected | false-positive |
out-of-scope | needs-review`. _Avoid_: 상태, 결과.

**Verification stage (확인 단계)**:
검출 하나를 확인하는 작업이 어디까지 진행됐는지. 판정과 별개 축이다.
_Avoid_: 진행률(조치 진행과 섞일 때).

**Adapter (어댑터)**:
스캐너 하나를 스킬에 붙이는 선언. `{id, category, intrusiveness, 가용성 확인,
실행 명령 템플릿, output_format}`. 선언은 데이터, 출력→SARIF 변환만 코드.
_Avoid_: 플러그인, 스캐너(도구 자체와 섞일 때).

**Normalizer (정규화기)**:
어댑터 출력을 SARIF로 바꾸는 공용 변환기. `output_format` 종류 수만큼만 있고
어댑터가 그 이름으로 가리킨다. _Avoid_: 파서.

**Fingerprint (지문)**:
검출의 위치 독립 식별자 — 파일·함수·검출 구문에서 만든다. 줄 번호에 의존하지
않는다. _Avoid_: ID(스캐너마다·차수마다 바뀌는 번호와 섞일 때).

**Evidence workbook (증적 워크북)**:
검출별 판정·근거를 고정 열로 담은 표. 열 정의는 고정 문서가 정본이다.
_Avoid_: 결과표, 엑셀.

**Cover report (표지 보고서)**:
점검의 범위·인가·방법·요약을 서술한 문서. 숫자는 증적 워크북에서 집계한다.
_Avoid_: 최종 보고서(워크북과 구분이 흐려질 때).

## Relationships

- 하나의 **Scope**는 하나 이상의 **Target**과 정확히 하나의 **Consent record**를 가진다.
- **Authorization gate**는 **Scope**를 읽어 통과/차단을 판정한다.
- **Scope**가 바뀌면 이전 게이트 통과(approval)는 자동 무효가 된다.
  "바뀜"은 **의미 필드**(targets의 type·value, exclusions, window, consent,
  침습도 수준) 기준이다. `notes` 같은 설명 필드 변경은 무효 사유가 아니다
  (2026-10-22 확정).

- 하나의 **Finding**은 하나의 **Disposition**과 하나의 **Verification stage**를
  가진다. 두 축은 독립이다(sast-remediation의 결론·작업 단계 분리와 같은 원리).
- 이 스킬은 **확인**까지만 추적한다. `confirmed` 코드 결함은 SARIF로
  sast-remediation에 넘기고, 코드 수정 진행은 그쪽이 추적한다. 같은 결함의
  진행을 두 스킬이 이중으로 들지 않는다 (2026-10-22 확정).
- 넘긴 **Finding**은 **Handed-off (넘김)** 표시를 가진다. 해소 여부는
  sast-remediation 기록을 읽어오지 않고 **다음 점검 차수의 재점검 결과**로만
  판단한다 — 같은 fingerprint의 검출이 사라졌으면 해소. 해소의 증거는 스캐너
  재실행이다 (2026-10-22 확정).
- 여러 스캐너의 검출은 **Fingerprint가 같고 CWE도 같을 때만** 하나의
  **Finding**으로 묶는다. 묶인 검출은 출처 스캐너 목록을 가진다. CWE가 다르면
  같은 줄이어도 별개 결함이다 (2026-10-22 확정).
- 같은 **Fingerprint**가 차수 간 해소 판단(재점검)과 스캐너 간 묶음 양쪽에 쓰인다.
- **Adapter** 실행 판정은 침습도 세 겹이다 (2026-10-22 확정):
  ① 어댑터 intrusiveness가 **Scope**의 intrusiveness 상한을 넘으면 금지,
  ② `active-nondestructive` 이하이고 사용자가 직접 실행을 명시하면 스킬이 실행,
  ③ 그 외(intrusive, 또는 미명시)는 운영자에게 명령을 지시한다.
  intrusive는 스코프 건별 인가 + 운영자 실행만.
- 하나의 점검은 하나의 **Evidence workbook**과 하나의 **Cover report**를 낸다.
  **Cover report**의 범위·인가 절에 **Scope**와 **Consent record**가 들어가고,
  그 안의 모든 숫자는 **Evidence workbook**에서 집계한다 — 둘의 불일치는
  validate 에러 (2026-10-22 확정).

## Example dialogue

> **Dev:** "Semgrep과 CodeQL이 같은 함수에서 둘 다 SQL 결합을 잡았는데, **Finding** 두 개야?"
> **보안 담당:** "**Fingerprint**랑 CWE가 같으면 하나. 출처 스캐너만 두 개로 남겨."
> **Dev:** "확인해 보니 진짜야. **Disposition**을 `confirmed`로 두고 고치면 끝?"
> **보안 담당:** "여기선 고치지 않아. SARIF로 sast-remediation에 넘기고 **Handed-off**로 표시해.
> 고쳐졌는지는 다음 차수 재점검에서 그 **Fingerprint**가 사라졌는지로 판단해."
> **Dev:** "**Scope**의 `notes`만 고쳤는데 게이트를 다시 통과해야 해?"
> **보안 담당:** "아니. 대상·제외·기간·동의·침습도 같은 의미 필드가 바뀔 때만."

## Flagged ambiguities

- **Authorization gate가 보장하는 것** (2026-10-22 확정): 정직한 실수
  방지(스코프 오타·잘못된 대상·기간 만료로 범위 밖을 치는 것)와 인가 주장의
  증적 기록, **둘 다**. 그러나 스킬은 동의가 진짜인지 검증할 수 없으므로
  **악의적 사용자는 막지 못한다** — 이 한계를 SKILL.md와 설계에 명시한다.
  게이트의 실제 보호는 "스킬이 사용자가 선언한 범위를 벗어나지 않는다"까지다.
