# Resilient skills: approved implementation scope

Historical design for the 1.12.0 / 0.4.0 implementation. Later commit, merge and
release status is recorded in [HANDOFF.md](../../../HANDOFF.md). Reading this
document does not request another implementation run.

The user approved implementing phases 1 and 2 of the 2026-09-09 recommendation: reliable manual resumption plus approval-scoped improvement. Automatic wake-up, background monitoring, autonomous deployment and expanded execution authority are excluded.

## Requirements
- SAST: preserve complete browser draft results across reload and backup/import; distinguish temporary browser storage from real file reconciliation.
- Preserve incomplete/provisional progress and notes where available. Recover only what records/backups support; name irrecoverable information, never silently reset it.
- Check damaged/stale state before summary/index use; checkpoint before code edits; reconcile unfinished edits and source-verification freshness before continuing.
- Use collision-free atomic writes and one cooperating writer for shared toolkit state. Do not claim distributed transactions or power-loss guarantees beyond the tested implementation.
- Record a source snapshot around verification; reject changed targets and prevent stale verified evidence from being trusted at resume. Report legacy evidence without manufacturing a snapshot.
- Carry over verified conclusions only when prior verification and current applicability are established.
- Architect: optional persistent improvement records with problem/reproduction, baseline/candidate, evaluation, authority reference, application verification and version/rollback information. It records and validates the workflow, never executes arbitrary patches/tests, grants approval, publishes, or starts itself.
- Text: fix broken generated lists/emphasis and align inputs, state/save meanings, responsibilities, terminology and output contracts.
- Preserve existing JSON enums/schemaVersion 1.0, fixed answer parser labels, JSON stdout contracts, source/user edits and old backups. Additive records must fail safely when malformed.
- All supported tools remain Python standard-library / browser-native JavaScript, offline and self-contained.
- Tests exercise behavior in temporary fixtures, including malformed inputs, interruption boundaries, reload, conflicts and negative approval cases.
- Canonical edits only in skills/ except Claude-specific agents, root docs and packaging. Copies are generated via scripts/sync-plugins.sh.
- Existing 1.11.0/0.3.0 changes remain intact. No commit, push, plugin install or running project upgrades in this implementation.
- Final versions: sast-remediation 1.12.0; skill-architect 0.4.0.

## Architecture
Keep results, provisional work, policy and browser drafts as distinct state domains. Add small reusable state/IO helpers rather than a resident agent platform. Add a separate architect improvement tracker and mode-specific reference. Existing execution remains user-invoked; authority comes from a verifiable user request, not a JSON label.

## Completion
Targeted RED/GREEN tests, complete existing/new Python and Node suites, source/copy and version checks, fresh review of scope and quality, and documented real-browser/power-loss limitations.
