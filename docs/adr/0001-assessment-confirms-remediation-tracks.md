# security-assessment는 확인까지만, 조치 진행은 sast-remediation이 추적한다

security-assessment는 검출의 판정과 확인 단계까지만 기록하고, `confirmed` 코드
결함은 SARIF로 sast-remediation에 넘긴 뒤 "넘김"으로 표시한다. 코드 수정 진행은
sast-remediation만 추적하며, 해소 여부는 상대 스킬의 기록을 읽지 않고 다음 차수의
재점검(같은 fingerprint 검출이 사라졌는지)으로만 판단한다. 같은 결함의 진행을 두
스킬이 이중으로 들면 어긋나고, 상대 스킬의 결과 형식에 의존하면 그쪽이 바뀔 때마다
깨지며, 점검 산출물에서 해소의 증거는 스캐너 재실행이어야 감사에서 설명되기 때문이다.

## Considered Options

- sast-remediation의 `security-results`를 역수입해 즉시 "조치됨" 표시 — 즉시성은
  좋지만 두 스킬이 서로의 파일 형식에 묶이고, 해소 판단이 상대 기록에 의존한다.
- 한 스킬에 점검+조치를 모두 넣기 — 게이트·산출물이 커지고 인가 게이트와 입력
  게이트의 성격이 섞인다.

## Consequences

- 넘긴 결함은 다음 점검 차수 전까지 security-assessment 쪽에서 "넘김"으로 남는다.
  즉시 해소 현황은 sast-remediation 대시보드에서 본다.
- 재점검에서 사라졌다고 바로 해소로 보지 않는다. 그 결함을 찾았던 어댑터가 그 차수에
  다시 돌았을 때만 해소이고, 돌지 않았으면 재확인 안 됨으로 남긴다. 스캐너를 돌리지
  않아 안 보이는 것과 고쳐진 것을 구분하기 위해서다.
