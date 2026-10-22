# security-assessment 툴킷

인가 기반 보안 취약점 점검 오케스트레이터. **현재 구현 범위는 M0 — 인가
게이트뿐이며 스캐너는 아직 없다.**

이 스킬은 **인가된 점검**만 수행한다. 게이트는 선언한 범위를 벗어나는 실수를
막고 인가 주장을 기록하지만, 동의가 진짜인지는 검증하지 못한다(악의적 사용자는
막지 못한다). 설계 정본은 저장소 루트 `CONTEXT.md`, `docs/adr/`,
`docs/superpowers/*/2026-10-14-security-assessment*`.

## 빠른 시작 (M0)

1. 이 디렉터리를 대상 프로젝트에 `security-assessment-toolkit/`으로 복사한다.
2. `data/scope.json`에 범위를 적는다(`examples/scope.json` 형식).
3. 다음을 실행한다.

```bash
python3 tools/assess_toolkit.py validate
python3 tools/assess_toolkit.py authorize
python3 tools/assess_toolkit.py gate
```

`gate`가 READY여야 이후 점검 단계로 간다. 상세 절차는 `prompts/00-authorize.md`.

## 명령

| 명령 | 용도 |
|---|---|
| `validate` | 스코프 형식·정합성 검사. `--strict`는 게이트 미통과도 에러 |
| `authorize` | 현재 스코프의 의미 지문 기록, status를 authorized로 |
| `gate` | 승인·지문·기간 재대조 → READY/BLOCKED |
| `adapters` | 어댑터별 실행 판정 표시(명령 미실행). `--direct`는 사용자가 직접 실행을 명시했다고 봄 |
| `scan` | 게이트 READY일 때 'run' 판정 어댑터를 실행하고 출력을 수집·묶어 data/findings.json에 쓴다. `--direct` 필요. operator 판정은 명령만 안내 |
| `dispositions` | 검출별 판정·확인 단계 집계(JSON). 레코드 없는 검출은 unreviewed로 센다 |
| `bridge` | confirmed 코드 결함을 SARIF(`data/handoff.sarif`)로 내보내고 handedOff 표시. `--dry-run`·`--all` |

## 테스트

```bash
python3 -B -m unittest tools.test_assess
```

원리는 `docs/HOW_IT_WORKS.md`, 버전 정책은 `docs/VERSIONING.md`.
