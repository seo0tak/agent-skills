# Input Validation

## Gate Status

- Status: `UNREVIEWED`
- Checked at:
- Decision owner:

허용 상태는 `UNREVIEWED`, `MECHANICAL_READY`, `READY`, `BLOCKED`입니다.
실제 분석과 조치는 `READY`에서만 시작합니다.

## Current Project

- Project root:
- Project identity:
- Identity evidence:
- Source roots found:
- Project declarations found:

## Input Files

### PDF

- Path:
- File signature valid:
- Project or system name:
- Analysis identifier:
- Generated at:
- Finding count:

### Spreadsheet

- Path:
- File structure valid:
- Project or system name:
- Analysis identifier:
- Generated at:
- Finding count:
- Finding data sheet:

## Match Review

| Check | Result | Evidence |
|---|---|---|
| PDF and spreadsheet belong to the same project |  |  |
| PDF and spreadsheet belong to the same analysis run |  |  |
| Finding counts are consistent |  |  |
| Reported source scope is compatible with the current source |  |  |
| Required finding fields are readable |  |  |

## Blockers

- None recorded.

## Gate Decision

`READY`는 모든 필수 파일이 유효하고, 현재 소스·PDF·스프레드시트가 같은
프로젝트와 검사 차수를 가리키며, 검출 목록을 정규화할 수 있을 때만
선언합니다. 근거가 부족하거나 불일치가 있으면 `BLOCKED`로 두고 다음
단계로 진행하지 않습니다.
