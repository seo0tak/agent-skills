# seo0tak Claude Skills

개인 Claude Code 스킬 마켓플레이스입니다.

## 설치

```bash
# 마켓플레이스 등록
claude plugin marketplace add seo0tak/claude-skills
# private 저장소면:
# claude plugin marketplace add git@github.com:seo0tak/claude-skills.git

# 플러그인 설치
claude plugin install sast-remediation@seo0tak-skills
claude plugin install skill-architect@seo0tak-skills
```

세션 안에서는 `/plugin marketplace add`, `/plugin install`로 동일하게 가능합니다.

## 업데이트 배포

이 저장소에 커밋·푸시하면 사용자 쪽에서는 다음으로 반영됩니다.

```bash
claude plugin marketplace update seo0tak-skills
```

## 플러그인 목록

| 플러그인 | 설명 | 버전 |
|---|---|---|
| sast-remediation | SAST 취약점 조치 워크플로우 (게이트·이월·증적·모델 티어링) | 1.7.0 |
| skill-architect | 스킬 아키텍처 감사·설계 (품질 체크리스트 10범주) | 0.1.0 |

버전 정본은 각 플러그인의 `.claude-plugin/plugin.json`입니다. 위 표는 요약이므로
버전을 올릴 때 함께 갱신합니다.

## 새 스킬 추가

1. `plugins/<이름>/` 디렉터리 생성
2. `.claude-plugin/plugin.json` 작성
3. `skills/<이름>/SKILL.md` 작성 (지원 파일 동봉 가능)
4. `.claude-plugin/marketplace.json`의 plugins 배열에 등록
