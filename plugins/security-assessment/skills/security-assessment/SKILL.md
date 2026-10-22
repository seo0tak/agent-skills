---
name: security-assessment
description: Run authorized security assessments — declare an authorization scope, gate on it, then orchestrate established open-source scanners (SAST/SCA/secrets/DAST/IaC), triage findings against source, and produce evidence. Confirmed code-level findings hand off to sast-remediation via SARIF. Use when the user asks to scan for vulnerabilities, run a security assessment or pentest, or check a target for security issues. | 인가된 보안 취약점 점검. 인가 범위를 선언하고 게이트를 통과한 뒤 검증된 오픈소스 스캐너를 조율해 검출·판정·증적을 만든다. 사용자가 보안 취약점 검사, 모의해킹, 취약점 점검, 보안 스캔을 요청하면 사용.
---

# 보안 취약점 점검 (security-assessment)

이 스킬 디렉터리의 `toolkit/`에 인가 기반 점검 툴킷이 들어 있다. **이 스킬은
인가된(authorized) 점검의 오케스트레이터**다. 검증된 오픈소스 스캐너를 조율하고,
모의해킹은 임의 대상 공격이 아니라 **인가 스코프 안에서 탐지를 확인·재현**하는
절차로 다룬다. 설계 정본은 저장소 루트 `CONTEXT.md`와 `docs/adr/`.

## 인가 게이트가 먼저다 (현재 구현 범위 = M1b)

어떤 점검도 인가 게이트가 READY가 되기 전에는 시작하지 않는다. 어댑터를 스킬이 직접 실행할지는 침습도로 판정한다(`adapters` 명령; ADR 0002).

1. `toolkit/data/scope.json`에 점검 범위를 선언한다(`examples/scope.json` 참고):
   대상(`targets`: repo|web|infra), 제외 자산, 기간, 소유자 동의 기록
   (`consent`: 인가자·역할·일자·티켓/문서 참조), 침습도 수준.
2. 사용자와 함께 대상이 실제 인가 범위인지, 제외 자산과 충돌이 없는지 확인한다.
3. `python3 toolkit/tools/assess_toolkit.py validate`로 형식을 검사한다.
4. `python3 toolkit/tools/assess_toolkit.py authorize`로 승인 지문을 기록한다.
5. `python3 toolkit/tools/assess_toolkit.py gate`가 READY인지 확인한다.

**게이트의 한계(반드시 인지)**: 스킬은 동의가 진짜인지, 인가자가 실제 권한이
있는지 검증할 수 없다. 게이트는 **범위를 벗어나는 실수를 막고 인가 주장을
기록**할 뿐, **악의적 사용자는 막지 못한다**. 범위 밖 대상·기간 만료·스코프
변경이면 게이트가 BLOCKED를 반환한다.

## 아직 없는 것

판정·증적(M2~), 웹/인프라(M3~M4)는 아직 구현되지 않았다.
계획은 `docs/superpowers/plans/2026-10-14-security-assessment.md`. 현재는 인가 게이트·어댑터 실행 판정에 더해 'run' 판정 어댑터의 실제 실행·SARIF 수집·지문/CWE 묶음(M1b)까지 동작한다. 판정·증적(M2~)은 아직 없다.

## 안 하는 것

- 임의 대상 공격 코드·익스플로잇·페이로드 생성, 대량 타겟팅, 자격증명 수집,
  제3자 서비스 침해, 탐지 회피.
- 인가 범위 밖 대상 점검.

## sast-remediation과의 관계

이 스킬은 취약점을 *검사*하고, sast-remediation은 결과를 *조치*한다. 확인된 코드
레벨 결함은 SARIF로 넘긴다. 같은 결함의 조치 진행은 sast-remediation이 추적하며,
이 스킬은 다음 차수 재점검으로만 해소를 판단한다 (`docs/adr/0001-*`).

## 산출물 위치

모든 산출물은 프로젝트의 `security-assessment-toolkit/` 아래에 둔다(이 스킬의
toolkit을 프로젝트로 복사해 사용). 정본은 파일, 규칙은 `validate`가 강제한다.
