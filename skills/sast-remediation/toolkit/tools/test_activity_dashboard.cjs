/* Production activity projection/rendering, using Node built-ins only. */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const childProcess = require("node:child_process");

function event(overrides = {}) {
  return { schemaVersion: "1.0", eventId: "e-1", recordedAt: "2026-09-15T01:00:00Z",
    workspaceId: "w-1", reportId: "r-1", operationId: "op-1", attemptId: "a-1",
    kind: "changed", action: "browser.state", outcome: "info", source: "browser", actor: "user",
    itemIds: ["F-001"], summary: "상태 변경", before: { workflowStatus: "todo" },
    after: { workflowStatus: "analyzed" }, evidence: [], important: true, ...overrides };
}
function nested(depth) {
  let value = {};
  for (let index = 0; index < depth; index++) value = { child: value };
  return value;
}
function load() {
  const window = {};
  const context = vm.createContext({ window, Date, Math });
  const target = path.join(__dirname, "../assets/activity.js");
  if (fs.existsSync(target)) vm.runInContext(fs.readFileSync(target, "utf8"), context);
  return window.SAST_ACTIVITY;
}
function api() {
  const value = load();
  assert.ok(value, "activity helper must implement history projection");
  return value;
}
function dom() {
  function element(tag) {
    const node = { tag, children: [], attributes: {}, className: "", _text: "",
      appendChild(child) { this.children.push(child); return child; },
      setAttribute(name, value) { this.attributes[name] = String(value); },
      get textContent() { return this._text + this.children.map(child => child.textContent).join(""); },
      set textContent(value) { this._text = String(value); this.children = []; },
    };
    Object.defineProperty(node, "innerHTML", { set() { throw new Error("untrusted HTML sink"); } });
    return node;
  }
  return { createElement: element };
}

test("activity helper rejects malformed, foreign, wrong-source and conflicting event histories", () => {
  const helper = api();
  const identity = { workspaceId: "w-1", browserOnly: true };
  assert.equal(helper.merge([], [event()], identity).length, 1);
  for (const patch of [{ workspaceId: "foreign" }, { source: "agent" },
    { kind: "invalid" }, { recordedAt: "2026-02-30T00:00:00Z" }, { important: "yes" }, { itemIds: {} },
    { before: [] }, { extra: true }]) {
    assert.throws(() => helper.merge([], [event(patch)], identity));
  }
  assert.throws(() => helper.merge([event()], [event({ summary: "different" })], identity), /충돌/);
  assert.equal(helper.merge([event()], [event()], identity).length, 1);
  assert.equal(helper.merge([], [event({ reportId: "older-report" })], identity).length, 1);
});

test("unfinished means no matching finish, never proof of crash or current running", () => {
  const helper = api();
  const events = [event({ kind: "started", outcome: "running" }),
    event({ eventId: "e-2", kind: "finished", outcome: "failed", attemptId: "other" })];
  assert.equal(helper.project(events).unfinished.length, 1);
  events.push(event({ eventId: "e-3", kind: "finished", outcome: "succeeded" }));
  assert.equal(helper.project(events).unfinished.length, 0);
  events[2].reportId = "other-report";
  assert.equal(helper.project(events).unfinished.length, 1);
  events[2].reportId = "r-1";
  events[2].action = "unrelated-action";
  assert.equal(helper.project(events).unfinished.length, 1);
});

test("activity filtering is independent, pages are limited to 50, and item histories keep identity", () => {
  const helper = api();
  const events = Array.from({ length: 57 }, (_, i) => event({ eventId: "e-" + i,
    summary: i === 56 ? "마지막 <script>" : "상태 변경", itemIds: [i % 2 ? "F-002" : "F-001"] }));
  const first = helper.select(events, { page: 1 });
  const last = helper.select(events, { page: 2 });
  assert.equal(first.events.length, 50);
  assert.equal(last.events.length, 7);
  assert.equal(helper.select(events, { itemId: "F-002" }).total, 28);
  assert.equal(helper.select(events, { search: "마지막" }).total, 1);
  assert.equal(helper.select(events, { from: "2026-09-16" }).total, 0);
  assert.equal(helper.select(events, { source: "toolkit" }).total, 0);
});

test("work view aggregates retries without letting an old failure hide the latest success", () => {
  const helper = api();
  const records = [
    event({ eventId: "start-1", kind: "started", outcome: "running", action: "remediation", source: "agent" }),
    event({ eventId: "finish-1", kind: "finished", outcome: "failed", action: "remediation", source: "agent",
      summary: "첫 시도 실패" }),
    event({ eventId: "start-2", attemptId: "a-2", kind: "started", outcome: "running", action: "remediation",
      source: "agent", recordedAt: "2026-09-15T02:00:00Z" }),
    event({ eventId: "finish-2", attemptId: "a-2", kind: "finished", outcome: "succeeded", action: "remediation",
      source: "agent", summary: "수정 적용", recordedAt: "2026-09-15T03:00:00Z" }),
  ];
  const selected = helper.selectAudience(records, { audience: "work" });
  assert.equal(selected.total, 1);
  assert.equal(selected.rows[0].outcome, "succeeded");
  assert.equal(selected.rows[0].attemptCount, 2);
  assert.deepEqual(Array.from(selected.rows[0].records, record => record.eventId),
    ["start-1", "finish-1", "start-2", "finish-2"]);
});

test("audience views separate routine operations while preserving important reconciliation and unknown records", () => {
  const helper = api();
  const records = [
    event({ eventId: "baseline", operationId: "baseline-op", attemptId: "baseline-a", action: "canonical.reconcile",
      kind: "observation", outcome: "info", source: "external", important: false, itemIds: [],
      summary: "기준 상태 관측", before: {}, after: { record: "data/progress.json" } }),
    event({ eventId: "drift", operationId: "drift-op", attemptId: "drift-a", action: "canonical.reconcile",
      kind: "changed", outcome: "info", source: "external", important: true,
      summary: "정본 변경 발견", after: { record: "data/progress.json", value: { workflowStatus: "analyzed" } } }),
    event({ eventId: "legacy", operationId: "legacy-op", attemptId: "legacy-a", action: "legacy.magic",
      source: "toolkit", important: false, summary: "과거 기록" }),
    event({ eventId: "work", operationId: "work-op", attemptId: "work-a", action: "verification",
      source: "agent", summary: "검증 실행" }),
  ];
  const original = JSON.stringify(records);
  const work = helper.selectAudience(records, { audience: "work" });
  const system = helper.selectAudience(records, { audience: "system" });
  assert.deepEqual(Array.from(work.rows, row => row.records[0].eventId), ["work", "drift"]);
  assert.deepEqual(Array.from(system.rows, row => [row.records[0].eventId, row.classification]),
    [["legacy", "unknown"], ["baseline", "system"]]);
  assert.equal(JSON.stringify(records), original);
});

test("audience filters return whole matching operations and never merge reports", () => {
  const helper = api();
  const records = [
    event({ eventId: "start-current", kind: "started", outcome: "running", action: "verification", source: "agent",
      recordedAt: "2026-09-14T23:59:00Z", summary: "검증 시작" }),
    event({ eventId: "finish-current", kind: "finished", outcome: "failed", action: "verification", source: "agent",
      recordedAt: "2026-09-15T01:00:00Z", summary: "테스트 실패" }),
    event({ eventId: "finish-other-report", reportId: "r-2", operationId: "op-2", kind: "finished", outcome: "failed",
      action: "verification", source: "agent", recordedAt: "2026-09-15T02:00:00Z", summary: "다른 차수 실패" }),
  ];
  const selected = helper.selectAudience(records, { audience: "work", mode: "errors", from: "2026-09-15",
    reportId: "r-1" });
  assert.equal(selected.total, 1);
  assert.deepEqual(Array.from(selected.rows[0].records, record => record.eventId), ["start-current", "finish-current"]);
});

test("audience date ranges require one underlying record inside both boundaries", () => {
  const helper = api();
  const records = [
    event({ eventId: "before-range", kind: "started", outcome: "running", action: "verification", source: "agent",
      recordedAt: "2026-09-14T23:59:00Z" }),
    event({ eventId: "after-range", kind: "finished", outcome: "succeeded", action: "verification", source: "agent",
      recordedAt: "2026-09-16T00:01:00Z" }),
  ];
  assert.equal(helper.selectAudience(records, { audience: "work", from: "2026-09-15", to: "2026-09-15" }).total, 0);
});

test("current operation outcome keeps the latest attempt terminal result after later detail records", () => {
  const helper = api();
  const records = [
    event({ eventId: "started", kind: "started", outcome: "running", action: "verification", source: "agent" }),
    event({ eventId: "failed", kind: "finished", outcome: "failed", action: "verification", source: "agent",
      recordedAt: "2026-09-15T02:00:00Z", summary: "검증 실패" }),
    event({ eventId: "detail", kind: "observation", outcome: "info", action: "verification", source: "agent",
      recordedAt: "2026-09-15T03:00:00Z", summary: "다음 확인 사항 기록" }),
  ];
  const row = helper.selectAudience(records, { audience: "work" }).rows[0];
  assert.equal(row.outcome, "failed");
  const document = dom(), container = document.createElement("div");
  helper.renderAudience(document, container, [row], {});
  assert.match(container.textContent, /최신 시도가 실패했습니다/);
});

test("canonical rows expose checkpoint guidance while system diagnostics label truncated detail as unknown", () => {
  const helper = api();
  const records = [
    event({ eventId: "checkpoint", operationId: "checkpoint-op", attemptId: "checkpoint-a",
      action: "canonical.reconcile", kind: "changed", source: "external", important: true,
      before: { record: "data/resume-state.json#F-001", value: { note: "이전 판단", nextAction: "소스 확인" } },
      after: { record: "data/resume-state.json#F-001", value: { note: "새 판단", nextAction: "관련 테스트 실행" } },
      summary: "정본 변경 발견" }),
    event({ eventId: "truncated", operationId: "truncated-op", attemptId: "truncated-a",
      action: "canonical.reconcile", kind: "changed", source: "external", important: true,
      before: { truncated: true, reason: "size limit" }, after: { truncated: true, reason: "size limit" },
      summary: "정본 변경 상세 생략" }),
  ];
  const work = helper.selectAudience(records, { audience: "work" });
  const system = helper.selectAudience(records, { audience: "system" });
  const document = dom(), container = document.createElement("div");
  helper.renderAudience(document, container, Array.from(work.rows).concat(Array.from(system.rows)), {});
  assert.match(container.textContent, /비고: 이전 판단 → 새 판단/);
  assert.match(container.textContent, /다음 확인: 소스 확인 → 관련 테스트 실행/);
  assert.match(container.textContent, /변경 상세가 생략되어.*원본.*대조/);
  assert.doesNotMatch(container.textContent, /수정자|실제 변경 시각/);
});

test("unfinished or failed system operations surface in work view without orphaning lifecycle records", () => {
  const helper = api();
  const records = [
    event({ eventId: "snapshot-start", operationId: "snapshot-op", attemptId: "snapshot-a", action: "snapshot",
      kind: "started", outcome: "running", source: "toolkit", summary: "스냅샷 시작" }),
    event({ eventId: "snapshot-failed", operationId: "snapshot-op", attemptId: "snapshot-a", action: "snapshot",
      kind: "finished", outcome: "failed", source: "toolkit", summary: "스냅샷 실패", recordedAt: "2026-09-15T02:00:00Z" }),
    event({ eventId: "sync-start", operationId: "sync-op", attemptId: "sync-a", action: "sync",
      kind: "started", outcome: "running", source: "toolkit", summary: "동기화 시작", recordedAt: "2026-09-15T03:00:00Z" }),
  ];
  const work = helper.selectAudience(records, { audience: "work" });
  const system = helper.selectAudience(records, { audience: "system" });
  assert.deepEqual(Array.from(work.rows, row => Array.from(row.records, record => record.eventId)),
    [["sync-start"], ["snapshot-start", "snapshot-failed"]]);
  assert.deepEqual(Array.from(system.rows, row => Array.from(row.records, record => record.eventId)),
    [["sync-start"], ["snapshot-start", "snapshot-failed"]]);
});

test("later informational detail cannot mask the latest unfinished lifecycle attempt", () => {
  const helper = api();
  const records = [
    event({ eventId: "sync-start", operationId: "sync-op", attemptId: "sync-a", action: "sync",
      kind: "started", outcome: "running", source: "toolkit", summary: "동기화 시작" }),
    event({ eventId: "sync-note", operationId: "sync-op", attemptId: "note-a", action: "sync",
      kind: "observation", outcome: "info", source: "toolkit", summary: "추가 확인 기록",
      recordedAt: "2026-09-15T02:00:00Z" }),
  ];
  const row = helper.selectAudience(records, { audience: "work" }).rows[0];
  assert.ok(row);
  assert.equal(row.currentUnfinished, true);
  assert.equal(row.outcome, "running");
});

test("work rows keep successful attempts separate from recorded verification status", () => {
  const helper = api();
  const value = event({ kind: "finished", outcome: "succeeded", action: "remediation", source: "agent",
    before: { verification: { status: "not-run" } }, after: { verification: { status: "passed" } },
    summary: "조치 저장 완료" });
  const row = helper.selectAudience([value], { audience: "work" }).rows[0];
  const document = dom(), container = document.createElement("div");
  helper.renderAudience(document, container, [row], {});
  assert.match(container.textContent, /현재 결과 시도 성공.*검증 완료 상태와 별도/);
  assert.match(container.textContent, /검증 상태: 미실행 → 통과/);
});

test("work rows explain field changes without claiming a browser status edit changed code", () => {
  const helper = api();
  const document = dom(), container = document.createElement("div");
  const value = event({ before: { workflowStatus: "todo", conclusion: "unreviewed" },
    after: { workflowStatus: "analyzed", conclusion: "needs-review" } });
  const row = helper.selectAudience([value], { audience: "work" }).rows[0];
  helper.renderAudience(document, container, [row], {});
  assert.match(container.textContent, /작업 단계: 미착수 → 분석 완료/);
  assert.match(container.textContent, /조치 결론: 미판정 → 추가 검토/);
  assert.match(container.textContent, /진단 상세/);
  assert.match(container.textContent, /이벤트: e-1/);
  assert.doesNotMatch(container.textContent, /코드 (?:수정|변경)|소스 (?:수정|변경)/);
});

test("native producer action names separate routine system operations from user-significant state work", () => {
  const helper = api();
  const events = [
    ...["state.checkpoint", "state.snapshot", "toolkit.gate"].map((action, index) => event({
      eventId: "system-" + index, operationId: "system-op-" + index, attemptId: "system-a-" + index,
      action, kind: "finished", outcome: "succeeded", source: "toolkit", important: action !== "toolkit.gate",
      summary: "작업 종료: " + action,
    })),
    ...["state.seal-verification", "state.recover-progress", "toolkit.scope"].map((action, index) => event({
      eventId: "work-" + index, operationId: "work-op-" + index, attemptId: "work-a-" + index,
      action, kind: "finished", outcome: "succeeded", source: "toolkit", important: true,
      summary: "작업 종료: " + action,
    })),
    event({ eventId: "checkpoint-failed", operationId: "failed-op", attemptId: "failed-a",
      action: "state.checkpoint", kind: "finished", outcome: "failed", source: "toolkit", important: true,
      summary: "작업 종료: 체크포인트 저장 (실패)" }),
  ];
  assert.deepEqual(Array.from(helper.selectAudience(events, { audience: "system" }).rows, row => row.action).sort(),
    ["state.checkpoint", "state.checkpoint", "state.snapshot", "toolkit.gate"].sort());
  assert.deepEqual(Array.from(helper.selectAudience(events, { audience: "work" }).rows, row => row.action).sort(),
    ["state.checkpoint", "state.recover-progress", "state.seal-verification", "toolkit.scope"].sort());
});

test("producer lifecycle halves pair within an attempt instead of inventing deletion and re-addition", () => {
  const helper = api();
  const events = [
    event({ eventId: "producer-start", action: "remediation", source: "agent", kind: "started", outcome: "running",
      before: { workflowStatus: "analyzed", note: "검토 완료" }, after: {}, summary: "조치 시작" }),
    event({ eventId: "producer-finish", action: "remediation", source: "agent", kind: "finished", outcome: "succeeded",
      before: {}, after: { workflowStatus: "change-complete", note: "수정 적용" }, summary: "조치 종료" }),
  ];
  const document = dom(), container = document.createElement("div");
  helper.renderAudience(document, container, helper.selectAudience(events, { audience: "work" }).rows, {});
  assert.match(container.textContent, /작업 단계: 분석 완료 → 변경 완료/);
  assert.match(container.textContent, /비고: 검토 완료 → 수정 적용/);
  assert.doesNotMatch(container.textContent, /undefined|분석 완료 → 미확인|미확인 → 변경 완료|검토 완료 → 미확인|미확인 → 수정 적용/);
});

test("paired lifecycle snapshots render nonmatching producer fields as one-sided observations", () => {
  const helper = api();
  const events = [
    event({ eventId: "scope-start", action: "toolkit.scope", source: "toolkit", kind: "started", outcome: "running",
      before: { minRisk: "high", reason: "승인 범위" }, after: {}, summary: "작업 시작: 처리 범위 변경" }),
    event({ eventId: "scope-finish", action: "toolkit.scope", source: "toolkit", kind: "finished", outcome: "succeeded",
      before: {}, after: { returnCode: 0 }, summary: "작업 종료: 처리 범위 변경 (성공)" }),
  ];
  const document = dom(), container = document.createElement("div");
  helper.renderAudience(document, container, helper.selectAudience(events, { audience: "work" }).rows, {});
  assert.match(container.textContent, /시작 시 최소 위험도: 높음/);
  assert.match(container.textContent, /시작 시 판단 이유: 승인 범위/);
  assert.doesNotMatch(container.textContent, /높음 → 미확인|승인 범위 → 미확인/);
});

test("attempt chronology keeps newer unfinished work current and surfaces any unresolved attempt", () => {
  const helper = api();
  const interleaved = [
    event({ eventId: "a-start", action: "toolkit.sync", source: "toolkit", kind: "started", outcome: "running",
      attemptId: "attempt-a", recordedAt: "2026-09-15T01:00:00Z" }),
    event({ eventId: "b-start", action: "toolkit.sync", source: "toolkit", kind: "started", outcome: "running",
      attemptId: "attempt-b", recordedAt: "2026-09-15T02:00:00Z" }),
    event({ eventId: "a-finish", action: "toolkit.sync", source: "toolkit", kind: "finished", outcome: "succeeded",
      attemptId: "attempt-a", recordedAt: "2026-09-15T03:00:00Z" }),
  ];
  const current = helper.selectAudience(interleaved, { audience: "work" }).rows[0];
  assert.equal(current.outcome, "running");
  assert.equal(current.currentUnfinished, true);

  const olderUnresolved = [interleaved[0], interleaved[1],
    event({ eventId: "b-finish", action: "toolkit.sync", source: "toolkit", kind: "finished", outcome: "succeeded",
      attemptId: "attempt-b", recordedAt: "2026-09-15T03:00:00Z" })];
  const selected = helper.selectAudience(olderUnresolved, { audience: "work", mode: "unfinished" });
  assert.equal(selected.total, 1);
  assert.equal(selected.rows[0].outcome, "succeeded");
  assert.equal(selected.rows[0].unfinishedAttemptCount, 1);
});

test("canonical audience classification uses recorded meaning rather than the important flag alone", () => {
  const helper = api();
  const events = [
    event({ eventId: "baseline", operationId: "baseline-op", attemptId: "baseline-a", action: "canonical.reconcile",
      kind: "observation", outcome: "info", source: "external", important: true, summary: "기준 상태 관측",
      before: {}, after: { record: "data/progress.json#F-001", value: { workflowStatus: "analyzed" } } }),
    event({ eventId: "hash", operationId: "hash-op", attemptId: "hash-a", action: "canonical.reconcile",
      kind: "changed", outcome: "info", source: "external", important: true, summary: "정본 변경 발견: src/a.c",
      before: { record: "src/a.c", sha256: "old", value: {} }, after: { record: "src/a.c", sha256: "new", value: {} } }),
    event({ eventId: "checkpoint", operationId: "checkpoint-op", attemptId: "checkpoint-a", action: "canonical.reconcile",
      kind: "changed", outcome: "info", source: "external", important: false, summary: "정본 변경 발견: data/resume-state.json",
      before: { record: "data/resume-state.json#F-001", value: { note: "이전", nextAction: "분석" } },
      after: { record: "data/resume-state.json#F-001", value: { note: "현재", nextAction: "테스트" } } }),
    event({ eventId: "unknown-shape", operationId: "unknown-op", attemptId: "unknown-a", action: "canonical.reconcile",
      kind: "changed", outcome: "info", source: "external", important: true, summary: "정본 변경 발견: custom.json",
      before: { record: "custom.json", value: { customDecision: "a" } },
      after: { record: "custom.json", value: { customDecision: "b" } } }),
  ];
  assert.deepEqual(Array.from(helper.selectAudience(events, { audience: "work" }).rows, row => row.records[0].eventId),
    ["checkpoint"]);
  assert.deepEqual(Array.from(helper.selectAudience(events, { audience: "system" }).rows, row => [row.records[0].eventId, row.classification]),
    [["unknown-shape", "unknown"], ["hash", "system"], ["baseline", "system"]]);
});

test("audience headings and risk values use plain Korean while diagnostics retain canonical identity", () => {
  const helper = api();
  const value = event({ action: "canonical.reconcile", kind: "changed", outcome: "info", source: "external", important: true,
    summary: "정본 변경 발견: data/project-profile.json", before: { record: "data/project-profile.json", value: { processingScope: { minRisk: "high" } } },
    after: { record: "data/project-profile.json", value: { processingScope: { minRisk: "critical" } } } });
  const document = dom(), container = document.createElement("div");
  helper.renderAudience(document, container, helper.selectAudience([value], { audience: "work" }).rows, {});
  assert.match(container.textContent, /^처리 범위 변경/);
  assert.match(container.textContent, /최소 위험도: 높음 → 매우 위험/);
  assert.doesNotMatch(container.children[0].children[0].textContent, /canonical|project-profile|정본 변경 발견/);
  assert.match(container.textContent, /작업: canonical\.reconcile/);
});

test("simple browser edits omit lifecycle outcome and attempt boilerplate", () => {
  const helper = api();
  const value = event({ action: "browser.note", kind: "changed", outcome: "info", source: "browser",
    summary: "브라우저 메모 변경", before: { note: "이전" }, after: { note: "현재" } });
  const document = dom(), container = document.createElement("div");
  helper.renderAudience(document, container, helper.selectAudience([value], { audience: "work" }).rows, {});
  assert.match(container.children[0].children[1].textContent, /변경 기록/);
  assert.doesNotMatch(container.children[0].children[1].textContent, /현재 결과 정보|시도 1회/);
});

test("event details render untrusted text without HTML and retain expandable accessible summaries", () => {
  const helper = api();
  const document = dom();
  const container = document.createElement("div");
  helper.render(document, container, [event({ summary: "<img src=x onerror=evil()>", evidence: ["<script>danger</script>"] })], {});
  assert.match(container.textContent, /<img src=x onerror=evil\(\)>/);
  assert.match(container.textContent, /<script>danger<\/script>/);
  assert.equal(container.children[0].tag, "details");
  assert.equal(container.children[0].children[0].tag, "summary");
});

test("new browser events redact explicit secret values without changing imported event identity", () => {
  const helper = api();
  const created = helper.create({ workspaceId: "w-1", reportId: "r-1", itemIds: ["F-001"],
    action: "browser.note", summary: "token=TOP_SECRET_VALUE", before: {}, after: { note: "password: TOP_SECRET_VALUE" } });
  assert.doesNotMatch(JSON.stringify(created), /TOP_SECRET_VALUE/);
  assert.match(JSON.stringify(created), /REDACTED/);
  assert.equal(helper.merge([], [event()])[0].eventId, "e-1");
});

test("event validation blocks lifecycle, ID, credential and size violations before import", () => {
  const helper = api();
  for (const patch of [{ eventId: "../escape" }, { kind: "started", outcome: "succeeded" },
    { kind: "finished", outcome: "info" }, { summary: "" }, { itemIds: [""] },
    { summary: "access_token=SECRET_VALUE" }, { before: { nested: { pwd: "SECRET_VALUE" } } },
    { evidence: ["Bearer SECRET_VALUE"] }, { summary: "한".repeat(12000) }]) {
    assert.throws(() => helper.merge([], [event(patch)]));
  }
  const ready = event({ summary: "access_token = [REDACTED]", after: { pwd: "[REDACTED]" } });
  assert.deepEqual(JSON.parse(JSON.stringify(helper.merge([], [ready]))), [ready]);
});

test("creation bounds oversized snapshots and identifies truncation without storing full source", () => {
  const helper = api();
  const created = helper.create({ workspaceId: "w-1", reportId: "r-1", action: "browser.draft",
    summary: "새 초안", after: { resultFiles: Array.from({ length: 50 }, () => "한".repeat(2500)) } });
  assert.ok(Buffer.byteLength(JSON.stringify(created, null, 2) + "\n") <= 32768);
  assert.equal(created.after.truncated, true);
});

test("browser and Python validators agree on identity, secrets, lifecycle and date boundaries", () => {
  const helper = api();
  const values = [event(), event({ reportId: "previous-round" }), event({ source: "external" }),
    event({ summary: "token = [REDACTED]", before: { password: "[REDACTED]" } }),
    helper.create({ workspaceId: "w-1", action: "browser.note", summary: "메모🔒", after: { note: "password='test secret'" } }),
    ...[{ eventId: "../x" }, { operationId: "a b" }, { kind: "finished", outcome: "info" },
      { recordedAt: "2026-02-30T10:00:00Z" }, { recordedAt: "0000-01-01T00:00:00Z" },
      { recordedAt: "2026-09-15T00:00:00+24:00" }, { before: [] }, { itemIds: [""] },
      { evidence: ["access_token=TEST_SECRET"] }, { summary: "한".repeat(12000) },
      { after: { pwd: "hidden" } }, { extra: true }].map(value => event(value))];
  const expected = values.map(value => { try { helper.validate(value); return true; } catch { return false; } });
  const boundaries = [
    { value: event({ before: nested(8) }), accepted: true },
    { value: event({ after: nested(9) }), accepted: false },
    ...["__proto__", "prototype", "constructor"].map(key => ({
      value: event({ before: JSON.parse('{"nested":{"' + key + '":"value"}}') }), accepted: false })),
    { value: event({ action: "canonical.reconcile" }), accepted: false },
    ...["2026-09-15 01:00:00Z", "20260915T010000Z", "2026-09-15T01:00Z"].map(recordedAt => ({
      value: event({ recordedAt }), accepted: false })),
  ];
  for (const boundary of boundaries) {
    const accepted = (() => { try { helper.validate(boundary.value); return true; } catch { return false; } })();
    assert.equal(accepted, boundary.accepted);
    values.push(boundary.value);
    expected.push(boundary.accepted);
  }
  const script = "import json,sys\nsys.path.insert(0,sys.argv[1])\nfrom sast_activity import validate_event\nresults=[]\nfor value in json.load(sys.stdin):\n try:\n  validate_event(value); results.append(True)\n except (ValueError,TypeError):\n  results.append(False)\nprint(json.dumps(results))";
  const actual = JSON.parse(childProcess.execFileSync("python3", ["-B", "-c", script, __dirname], { input: JSON.stringify(values), encoding: "utf8" }));
  assert.deepEqual(actual, expected);
});

test("event summaries display compact UTC dates while details preserve original precision and unknown actor", () => {
  const helper = api();
  const document = dom(), container = document.createElement("div");
  const value = event({ recordedAt: "2026-09-15T13:29:48.224039+09:00", actor: "unknown" });
  const original = JSON.stringify(value);
  helper.render(document, container, [value], {});
  const entry = container.children[0];
  assert.match(entry.children[0].textContent, /2026-09-15 04:29:48 UTC/);
  assert.doesNotMatch(entry.children[0].textContent, /224039|T13:29/);
  assert.match(entry.children[1].textContent, /기록 시각\(원문\): 2026-09-15T13:29:48\.224039\+09:00/);
  assert.match(entry.children[1].textContent, /기록 주체: 미확인/);
  assert.equal(JSON.stringify(value), original);
});

test("date presentation safely labels invalid input and does not change chronological ordering", () => {
  const helper = api();
  assert.equal(typeof helper.formatTimestamp, "function");
  for (const value of [null, undefined, {}, "bad date", "2026-02-30T00:00:00Z", "0000-01-01T00:00:00Z"]) {
    assert.equal(helper.formatTimestamp(value), "미확인");
  }
  const values = [event({ eventId: "older", recordedAt: "2026-09-15T09:00:00.999999+09:00" }),
    event({ eventId: "newer", recordedAt: "2026-09-15T00:00:01.000001Z" })];
  const original = JSON.stringify(values);
  const selected = helper.select(values, {}).events;
  assert.deepEqual(Array.from(selected, entry => entry.eventId), ["newer", "older"]);
  assert.deepEqual(Array.from(selected, entry => helper.formatTimestamp(entry.recordedAt)), ["2026-09-15 00:00:01 UTC", "2026-09-15 00:00:00 UTC"]);
  assert.equal(JSON.stringify(values), original);
});

test("browser histories reject reserved canonical reconciliation actions before import", () => {
  const helper = api();
  assert.throws(() => helper.merge([], [event({ action: "canonical.reconcile" })]), /예약|내부|출처/);
  assert.equal(helper.merge([], [event({ action: "browser.reconcile" })]).length, 1);
});

test("import rejects reserved metadata keys and excessive nesting without silently rewriting records", () => {
  const helper = api();
  for (const key of ["__proto__", "prototype", "constructor"]) {
    const value = event({ before: JSON.parse('{"nested":{"' + key + '":"untrusted"}}') });
    const original = JSON.stringify(value);
    assert.throws(() => helper.merge([], [value]), /키|허용/);
    assert.equal(JSON.stringify(value), original);
  }
  assert.equal(helper.merge([], [event({ before: nested(8) })]).length, 1);
  assert.throws(() => helper.merge([], [event({ after: nested(9) })]), /깊/);
});

test("new snapshot compaction records omitted reserved keys while preserving safe metadata", () => {
  const helper = api();
  const before = JSON.parse('{"safe":"keep","__proto__":"a","prototype":"b","constructor":"c","nested":{"constructor":"d","value":5}}');
  const original = JSON.stringify(before);
  const created = helper.create({ workspaceId: "w-1", action: "browser.draft", summary: "초안", before });
  assert.equal(created.before.safe, "keep");
  assert.deepEqual(Array.from(created.before._omittedKeys || []), ["__proto__", "prototype", "constructor"]);
  assert.deepEqual(Array.from(created.before.nested._omittedKeys || []), ["constructor"]);
  for (const key of ["__proto__", "prototype", "constructor"]) assert.equal(Object.hasOwn(created.before, key), false);
  assert.equal(created.before.nested.value, 5);
  assert.equal(JSON.stringify(before), original);
  const crowded = JSON.parse('{"__proto__":0,"prototype":0,"constructor":0}');
  for (let index = 0; index < 51; index++) crowded["safe" + index] = index;
  const compacted = helper.create({ workspaceId: "w-1", action: "browser.draft", summary: "초안", before: crowded }).before;
  assert.equal(compacted.safe49, 49);
  assert.equal(compacted._truncated, 1);
});

test("JavaScript and Python both reject raw non-finite JSON numbers rather than accepting JSON null", () => {
  const helper = api();
  for (const value of [NaN, Infinity, -Infinity]) assert.throws(() => helper.validate(event({ after: { number: value } })));
  const rawEvents = "[" + ["NaN", "Infinity", "-Infinity"].map(number => JSON.stringify(event({ after: { number: "REPLACE_NONFINITE" } })).replace('"REPLACE_NONFINITE"', number)).join(",") + "]";
  assert.throws(() => JSON.parse(rawEvents));
  const script = "import json,sys\nsys.path.insert(0,sys.argv[1])\nfrom sast_activity import validate_event\nresults=[]\nfor value in json.load(sys.stdin):\n try:\n  validate_event(value); results.append(True)\n except (ValueError,TypeError):\n  results.append(False)\nprint(json.dumps(results))";
  const actual = JSON.parse(childProcess.execFileSync("python3", ["-B", "-c", script, __dirname], { input: rawEvents, encoding: "utf8" }));
  assert.deepEqual(actual, [false, false, false]);
});

test("operation identity conflicts reject whole merges while actor changes and internal observations remain compatible", () => {
  const helper = api();
  const first = event({ itemIds: ["F-001", "F-002"] });
  const next = event({ eventId: "e-2", attemptId: "a-2", itemIds: ["F-002", "F-001"], actor: "second-user" });
  assert.equal(helper.merge([first], [next]).length, 2);
  for (const patch of [{ workspaceId: "w-2" }, { reportId: "r-2" }, { action: "browser.draft" },
    { source: "agent" }, { itemIds: ["F-003"] }]) {
    assert.throws(() => helper.merge([first], [{ ...next, ...patch }]), /논리|작업.*충돌/);
  }
  const canonical = event({ eventId: "e-3", action: "canonical.reconcile", kind: "observation", source: "external", itemIds: [] });
  assert.equal(helper.merge([first], [canonical]).length, 2);
});

test("Python and browser batch validators agree on logical operation identity boundaries", () => {
  const helper = api();
  const first = event({ itemIds: ["F-001", "F-002"] });
  const second = event({ eventId: "e-2", attemptId: "a-2", actor: "second-user", itemIds: ["F-002", "F-001"] });
  const fixtures = [
    { records: [first, second], accepted: true },
    ...[{ workspaceId: "other" }, { reportId: "other" }, { action: "browser.draft" },
      { source: "agent" }, { itemIds: ["F-003"] }].map(patch => ({ records: [first, { ...second, ...patch }], accepted: false })),
    { records: [first, { ...second, source: "external", kind: "observation", action: "canonical.reconcile", itemIds: [] }], accepted: true },
  ];
  for (const fixture of fixtures) {
    let accepted = true;
    try { helper.merge([], fixture.records); } catch { accepted = false; }
    assert.equal(accepted, fixture.accepted);
  }
  const script = "import json,sys\nsys.path.insert(0,sys.argv[1])\nfrom sast_activity import validate_event,lifecycle_issues\nresults=[]\nfor values in json.load(sys.stdin):\n try:\n  [validate_event(value) for value in values]; results.append(not lifecycle_issues(values))\n except (ValueError,TypeError):\n  results.append(False)\nprint(json.dumps(results))";
  const actual = JSON.parse(childProcess.execFileSync("python3", ["-B", "-c", script, __dirname], { input: JSON.stringify(fixtures.map(fixture => fixture.records)), encoding: "utf8" }));
  assert.deepEqual(actual, fixtures.map(fixture => fixture.accepted));
});
