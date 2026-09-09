# Editorial copy polish — progress

Plan: 2026-09-09-editorial-copy-polish.md. Baseline 0e21db3; branch codex/editorial-copy-polish.

## Preflight

| Tasks | Shared contract | Resolution |
|---|---|---|
| 1 / 3 | UI labels and guide descriptions | Task 3 owns HTML/JS; Task 1 owns USAGE.md. Same labels in briefs. |
| 2 / 4 | Decision log text | Task 4 owns generator; Task 2 leaves generated DECISION_LOG untouched. |
| 1–4 / 5 | Generated artifacts and packaging | Only root syncs once edits settle. |
| 1 | Guidance prose and existing doc contracts | No schema/data/authority changes. |
| 2 | Human JSON text and required metadata | No enum/key/required-array changes. |
| 3 | UI output and existing state behavior | Preserve DOM IDs/storage/parser, test consumers. |
| 4 | CLI output and record invariants | Human message changes, snapshot/authority logic unchanged. |
| 5 | Publication | User requested edits and push; previous target main retained. No force push. |

Baseline: SAST Python 82/82; Architect Python 24/24; browser 44/44. LSP tools are unavailable; use syntax checks and existing tests. A sandbox restriction on Git ref writes was resolved through the approval mechanism before branch creation.

- [x] Task 1 guidance
- [x] Task 2 prompts/templates/schemas
- [x] Task 3 UI
- [x] Task 4 root/Architect/CLI
- [x] Task 5 integration and independent review

Publication follows the plan's Git procedure. The commit and remote result are recorded
in Git and the final user handoff, not in a self-referential commit-hash field here.

Scope: editorial corrections, existing guide contract errors and output clarity; optional new UI features and model-training/automation redesign are excluded. Human prose is reviewed by meaning; tests must exercise consumers, not merely grep expected source strings. No real-browser or repeated model benchmark claim.

## Integration evidence

- SAST SARIF-only preflight regression: RED (two wrong-mode message assertions), GREEN.
- UI request/export/global-and-item-reread consumers: RED 0/4, GREEN 4/4; full Node 48/48.
- Old malformed-progress message assertion failed after copy correction; updated to check
  the named file, original-preservation guidance, and unchanged original bytes. GREEN.
- First integration: SAST 83/83, Architect 24/24, Node 48/48, packaging 1/1.
  Generated toolkit output and plugin mirrors synchronized; validate has only the expected
  empty-input warning; version/mirror/whitespace checks passed.
- Independent review found five actionable corrections; all were fixed. A subsequent
  ordinary-build-file discovery omission was also restored. Focused re-review found no
  remaining Critical/Important/Minor issues. No schema, state, or permission expansion.
- Final tests: SAST 83/83, Architect 24/24, Node 52/52, packaging 1/1 (160 total).
  Mirrored Node suite 52/52 also passed. Counts include identical-record equality,
  cached/no-cache failed reloads and dynamic accessibility names. Syntax/mirror/version/
  whitespace checks passed; actual-browser certification remains unperformed.
- Publication target confirmed as origin/main; fetch precedes fast-forward integration.
- Limited independent consumer check passed: documented Architect capture input and summary
  in a temporary record directory; SAST representative guide with six base fields plus
  groupGuideRef and no delta in a temporary toolkit. No full-workflow benchmark claim.
