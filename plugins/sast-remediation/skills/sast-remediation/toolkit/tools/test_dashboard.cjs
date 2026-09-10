/* Run with: node --test tools/test_dashboard.cjs (Node.js built-ins only). */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const scriptPath = path.join(__dirname, "../assets/checklist.js");
const source = fs.readFileSync(scriptPath, "utf8");
const DAY_1 = "2026-09-01T00:00:00Z";
const DAY_2 = "2026-09-02T00:00:00Z";
const DAY_3 = "2026-09-03T00:00:00Z";

function item(workflowStatus = "todo", conclusion = "unreviewed", note = "", updatedAt = DAY_1) {
  return { workflowStatus, conclusion, note, updatedAt };
}

function backup(items, workspaceId = "project-A", schemaVersion = "1.0") {
  return { schemaVersion, workspaceId, updatedAt: DAY_3, items };
}

function result({
  id = "F-001", workflowStatus = "change-complete", conclusion = "fix",
  diff = "- old();\n+ checked();\n", updatedAt = DAY_2,
} = {}) {
  return {
    schemaVersion: "1.0", id, sequence: Number(id.replace(/^F-/, "")), workflowStatus, conclusion,
    reason: "Validated fix", resultFiles: ["src/example.c"], resultSummary: "Added a check",
    resultCodeDiff: diff, resultGuideComparison: "Matches the checker guidance", impact: ["caller"],
    verification: { status: "not-run", commands: [], results: [], limitations: [], verifiedAt: null },
    duplicates: [], evidenceNote: "Review the source file", updatedAt,
  };
}

function draft(resultValue, savedAt = DAY_3) {
  return { source: "browser-answer", savedAt, result: resultValue };
}

function loadDashboard({
  workspaceId = "project-A", fileItems = {}, fileResults = {}, storage = new Map(),
  findingCount = 1, bootstrap = false, inputStatus = "ready", scriptLoadSucceeds = false,
} = {}) {
  const elements = new Map();
  const blobs = new Map();
  const downloads = [];
  const selections = new Map();
  const documentListeners = {};
  const copiedText = [];
  let activeElement;
  let createdCount = 0;
  function element(id) {
    if (!elements.has(id)) {
      const classes = new Set();
      elements.set(id, {
        id, value: "", textContent: "", hidden: false, style: {}, dataset: {}, listeners: {},
        attributes: {}, children: [], isConnected: true,
        classList: {
          add(...names) { names.forEach((name) => classes.add(name)); },
          remove(...names) { names.forEach((name) => classes.delete(name)); },
          toggle(name, on) { if (on) classes.add(name); else classes.delete(name); },
          contains(name) { return classes.has(name); },
        },
        addEventListener(type, listener) { this.listeners[type] = listener; },
        appendChild(child) { this.children.push(child); child.parentElement = this; },
        remove() { this.isConnected = false; }, select() {},
        setAttribute(name, value) { this.attributes[name] = String(value); },
        getAttribute(name) { return this.attributes[name] ?? null; },
        focus() { activeElement = this; },
        getClientRects() { return this.hidden ? [] : [{}]; },
        contains(candidate) { return candidate === this || this.children.some((child) => child.contains(candidate)); },
        querySelectorAll() { return this.focusable || []; },
        querySelector() { return this.children[0]; },
        closest(selector) {
          if (selector === "th") return this.parentElement;
          return this;
        },
        click() {
          if (this.href) {
            const raw = blobs.get(this.href);
            let data;
            try { data = JSON.parse(raw); } catch {}
            downloads.push({ name: this.download, raw, data });
          }
        },
      });
    }
    return elements.get(id);
  }
  const window = {
    SAST_TOOLKIT_DATA: {
      inputValidation: { status: inputStatus, blockers: [] },
      projectProfile: { workspaceId },
      findings: Array.from({ length: findingCount }, (_, index) => ({ id: "F-" + String(index + 1).padStart(3, "0"), sequence: index + 1 })),
      progress: backup(fileItems, workspaceId),
    },
    SAST_ITEM_RESULTS: fileResults,
  };
  const context = vm.createContext({
    window,
    document: {
      getElementById: element, createElement: (tag) => element("created-" + tag + "-" + createdCount++),
      body: element("body"), head: { appendChild(script) { scriptLoadSucceeds ? script.onload() : script.onerror(); } },
      querySelectorAll: (selector) => selections.get(selector) || [],
      addEventListener(type, listener) { documentListeners[type] = listener; },
      get activeElement() { return activeElement; },
    },
    localStorage: { getItem: (key) => storage.get(key) || null, setItem: (key, value) => storage.set(key, value) },
    navigator: { clipboard: { writeText: async (text) => { copiedText.push(text); } } },
    Blob: class { constructor(parts) { this.contents = parts.join(""); } },
    URL: {
      createObjectURL(blob) { const url = "blob:" + blobs.size; blobs.set(url, blob.contents); return url; },
      revokeObjectURL() {},
    },
    FileReader: class {
      readAsText(file) { this.result = file.text; this.onload(); }
    },
    setTimeout() {}, clearTimeout() {}, Date, Node: Object,
  });
  // Expose the existing closure only in this harness. Rendering requires
  // separate browser verification; this minimal DOM double checks storage,
  // merging, parser, downloads and event handlers use production logic without
  // a test hook in shipped JavaScript. Selected DOM effects can also be checked.
  const seam = "  initializeHeader();";
  assert.equal(source.split(seam).length, 2, "dashboard bootstrap seam must be unique");
  vm.runInContext(source.replace(seam, `
    render = function () {
      if (window.renderRecommendationsForTest) renderRecommendations();
      if (window.renderTableForTest) renderTable(findings);
    };
    renderCurrentDetail = function () {};
    window.testApi = { stateFor, updateState, importProgressData, exportProgress,
      parseAnswer, exportCurrentResult, bindEvents, renderSyncNotice, openDetail,
      closeDetail, renderDashboardFilter, updateSortIndicators, renderTable,
      resultProvenance, formatCheckerGuide, renderStats, renderRecommendations,
      importAccounting: function () { return lastImportAccounting; },
      setCurrent: function (id) { currentFindingId = id; } };
    ${bootstrap ? "" : "return;"}
${seam}`), context, { filename: scriptPath });
  return { api: window.testApi, element, storage, downloads, documentListeners,
    select: (selector, values) => selections.set(selector, values),
    active: () => activeElement, copiedText,
    useTableRendering: () => { window.renderTableForTest = true; },
    useRecommendationRendering: () => {
      window.renderRecommendationsForTest = true;
      element("recommendationLimit").value = "10";
      const list = element("recommendations");
      list.scrollTop = 0;
      // Model the DOM's removal of descendants and an empty scroll area's
      // offset clamping. This tests our restoration, not browser layout.
      Object.defineProperty(list, "textContent", {
        get() { return ""; },
        set() {
          function disconnect(node) {
            node.isConnected = false;
            node.children.forEach(disconnect);
          }
          this.children.forEach(disconnect);
          this.children = [];
          this.scrollTop = 0;
        },
      });
    } };
}

test("ready prompt and empty guide stay input-neutral while preserving the parser contract", async () => {
  const dashboard = loadDashboard({ bootstrap: true });
  dashboard.api.setCurrent("F-001");
  await dashboard.element("copyTaskPrompt").listeners.click();

  assert.match(dashboard.element("readinessMessage").textContent, /선택한 입력 자료/);
  assert.match(dashboard.api.formatCheckerGuide(null), /PDF를 사용하지 않은 입력에서는 비어 있을 수 있습니다/);
  const prompt = dashboard.copiedText[0];
  assert.match(prompt, /제공된 체커 공통 가이드가 있으면/);
  assert.doesNotMatch(prompt, /PDF 체커 가이드/);
  assert.match(prompt, /라벨과 콜론은 결과 추출에 사용하므로 그대로 유지/);
  for (const label of [
    "조치 결론:", "판단 이유:", "실제 변경 파일/위치:", "적용 내용:",
    "기존/수정 코드 비교:", "공통 가이드 부합 여부:", "영향 범위:", "검증:",
    "중복 처리 항목:", "체크리스트 비고 문구:",
  ]) assert.ok(prompt.includes(label), `missing fixed parser label: ${label}`);
  assert.equal(dashboard.api.stateFor("F-001").workflowStatus, "todo");
  assert.equal(dashboard.storage.size, 0);
});

test("result export explains existing and synthesized downloads without promoting state", () => {
  const existing = loadDashboard({ fileResults: { "F-001": result() } });
  existing.api.setCurrent("F-001");
  existing.api.bindEvents();
  existing.element("exportResult").listeners.click();
  assert.equal(existing.downloads[0].data.resultCodeDiff, "- old();\n+ checked();\n");
  assert.match(existing.element("toast").textContent, /현재 표시 중인 처리 결과.*다운로드를 요청/);
  assert.match(existing.element("toast").textContent, /정본 파일 저장이나 검증 완료를 뜻하지 않습니다/);
  assert.equal(existing.api.stateFor("F-001").workflowStatus, "todo");

  const synthesized = loadDashboard();
  synthesized.api.setCurrent("F-001");
  synthesized.api.bindEvents();
  synthesized.element("exportResult").listeners.click();
  assert.equal(synthesized.downloads[0].data.verification.status, "not-run");
  assert.match(synthesized.element("toast").textContent, /미검증 JSON 초안.*다운로드를 요청/);
  assert.match(synthesized.element("toast").textContent, /정본 파일 저장이나 검증 완료를 뜻하지 않습니다/);
  assert.equal(synthesized.api.stateFor("F-001").workflowStatus, "todo");
  assert.equal(synthesized.storage.size, 0);
});

test("global result reread reports index loading separately from included state targets", async () => {
  const dashboard = loadDashboard({
    fileItems: { "F-001": item("verified", "fix", "newer state", DAY_3) },
    fileResults: { "F-001": result({ updatedAt: DAY_2 }) },
    bootstrap: true,
    scriptLoadSucceeds: true,
  });
  await dashboard.element("refreshResults").listeners.click();
  assert.equal(dashboard.element("toast").textContent, "처리 결과 인덱스를 다시 읽었습니다. 진행상태 반영 대상: 0개(동일 내용 포함).");
  assert.equal(dashboard.api.stateFor("F-001").workflowStatus, "verified");
});

test("global reread count identifies an identical existing result as an included target", async () => {
  const existing = result({ updatedAt: DAY_2 });
  const dashboard = loadDashboard({
    fileItems: { "F-001": item("change-complete", "fix", "Review the source file", DAY_2) },
    fileResults: { "F-001": existing },
    bootstrap: true,
    scriptLoadSucceeds: true,
  });
  const before = { ...dashboard.api.stateFor("F-001") };
  await dashboard.element("refreshResults").listeners.click();
  assert.equal(dashboard.element("toast").textContent, "처리 결과 인덱스를 다시 읽었습니다. 진행상태 반영 대상: 1개(동일 내용 포함).");
  assert.deepEqual({ ...dashboard.api.stateFor("F-001") }, before);
});

test("item result reread names the file outcome and preserves newer workflow state", async () => {
  const dashboard = loadDashboard({
    fileItems: { "F-001": item("verified", "fix", "newer state", DAY_3) },
    fileResults: { "F-001": result({ updatedAt: DAY_2 }) },
    bootstrap: true,
    scriptLoadSucceeds: true,
  });
  dashboard.api.setCurrent("F-001");
  await dashboard.element("refreshResult").listeners.click();
  assert.equal(dashboard.element("toast").textContent, "이 항목 파일 결과를 다시 읽었습니다. 진행상태에 새로 반영된 내용은 없습니다.");
  assert.equal(dashboard.api.stateFor("F-001").workflowStatus, "verified");
});

test("failed item script load reports failure even when a cached result remains available", async () => {
  const dashboard = loadDashboard({
    fileItems: { "F-001": item("verified", "fix", "newer state", DAY_3) },
    fileResults: { "F-001": result({ updatedAt: DAY_2 }) },
    bootstrap: true,
    scriptLoadSucceeds: false,
  });
  dashboard.api.setCurrent("F-001");
  await dashboard.element("refreshResult").listeners.click();
  assert.equal(dashboard.element("toast").textContent, "이 항목 파일 결과를 다시 읽지 못했습니다. 이전에 읽은 결과를 유지합니다.");
  assert.equal(dashboard.api.stateFor("F-001").workflowStatus, "verified");
});

test("failed item script load without a cached result gives recovery guidance", async () => {
  const dashboard = loadDashboard({ bootstrap: true, scriptLoadSucceeds: false });
  const before = { ...dashboard.api.stateFor("F-001") };
  dashboard.api.setCurrent("F-001");
  await dashboard.element("refreshResult").listeners.click();
  assert.equal(dashboard.element("toast").textContent, "이 항목 파일 결과를 읽지 못했습니다. 파일 경로와 sync 결과를 확인하세요.");
  assert.deepEqual({ ...dashboard.api.stateFor("F-001") }, before);
  assert.equal(dashboard.storage.size, 0);
});

test("dynamic stat filter names include the displayed count", () => {
  const dashboard = loadDashboard();
  dashboard.api.renderStats("riskStats", { high: 3 }, { high: "높음" }, "risk");
  const button = dashboard.element("riskStats").children[0].children[0];
  assert.equal(button.getAttribute("aria-label"), "높음 3개로 목록 필터링");
});

test("a parsed full result survives reload and exports the exact diff bytes", () => {
  const storage = new Map();
  const first = loadDashboard({ storage });
  first.api.setCurrent("F-001");
  first.element("answerInput").value = "조치 결론: 수정\n기존/수정 코드 비교:\n```diff\n- old();\n+ checked();\n```\n검증: 확인";
  first.api.parseAnswer();

  const next = loadDashboard({ storage });
  next.api.setCurrent("F-001");
  next.api.exportCurrentResult();
  assert.equal(next.api.stateFor("F-001").workflowStatus, "change-complete");
  assert.equal(next.downloads[0].data.resultCodeDiff, "- old();\n+ checked();\n");
});

test("a state backup restores full draft results in a fresh browser context", () => {
  const first = loadDashboard();
  first.api.setCurrent("F-001");
  first.element("answerInput").value = "조치 결론: 수정\n판단 이유: 경계 검사 추가\n기존/수정 코드 비교:\n```diff\n- old();\n+ checked();\n```\n검증: 확인";
  first.api.parseAnswer();
  first.api.exportProgress();
  assert.equal(first.downloads[0].data.draftResults["F-001"].source, "browser-answer");

  const fresh = loadDashboard();
  assert.equal(fresh.api.importProgressData(first.downloads[0].data), 1);
  fresh.api.setCurrent("F-001");
  fresh.api.exportCurrentResult();
  assert.equal(fresh.downloads[0].data.reason, "경계 검사 추가");
  assert.equal(fresh.downloads[0].data.resultCodeDiff, "- old();\n+ checked();\n");
});

test("malformed and foreign draft records reject the whole backup atomically", () => {
  const dashboard = loadDashboard();
  dashboard.api.updateState("F-001", { note: "keep me" });
  const before = Array.from(dashboard.storage.entries());
  const cases = [
    null,
    { "F-001": { source: "browser-answer", savedAt: DAY_3, result: { id: "F-001" } } },
    { "F-001": draft(result({ id: "F-999" })) },
    { "F-999": draft(result({ id: "F-999" })) },
  ];
  for (const draftResults of cases) {
    assert.throws(
      () => dashboard.api.importProgressData({ ...backup({ "F-001": item("verified") }), draftResults }),
      /draft|초안|항목|ID/i,
    );
    assert.equal(dashboard.api.stateFor("F-001").note, "keep me");
    assert.deepEqual(Array.from(dashboard.storage.entries()), before);
  }
});

test("production bootstrap and later actions preserve a rejected current-key envelope byte for byte", () => {
  const key = 'sast-toolkit-progress:v2:"project-A"';
  const invalid = result({ diff: "ONLY_BROWSER_COPY" });
  invalid.sequence = "wrong-type";
  const raw = JSON.stringify({
    ...backup({ "F-001": item() }),
    draftResults: { "F-001": draft(invalid) },
  });
  const storage = new Map([[key, raw]]);

  const dashboard = loadDashboard({
    storage,
    fileResults: { "F-001": result({ diff: "CANONICAL_COPY" }) },
    bootstrap: true,
  });
  assert.equal(storage.get(key), raw, "startup must not replace rejected raw bytes");
  dashboard.api.updateState("F-001", { note: "later in-memory edit" });
  assert.equal(storage.get(key), raw, "ordinary later saves remain blocked pending explicit recovery");
  assert.match(storage.get(key), /ONLY_BROWSER_COPY/);
  assert.match(dashboard.element("localSaveStatus").textContent, /유지|복구|불러오기/);
});

test("a rejected current-key envelope has an exact recovery download without unlocking writes", () => {
  const key = 'sast-toolkit-progress:v2:"project-A"';
  const invalid = result({ diff: "ONLY_IN_REJECTED_RAW" });
  invalid.sequence = "wrong-type";
  const raw = " \n" + JSON.stringify({
    ...backup({ "F-001": item() }),
    draftResults: { "F-001": draft(invalid) },
  }) + "\n ";
  const storage = new Map([[key, raw]]);
  const dashboard = loadDashboard({
    storage,
    fileResults: { "F-001": result({ diff: "CANONICAL_IN_MEMORY" }) },
    bootstrap: true,
  });
  const recovery = dashboard.element("exportRejectedStorage");
  assert.equal(recovery.hidden, false);
  const beforeState = { ...dashboard.api.stateFor("F-001") };

  recovery.listeners.click();
  assert.equal(dashboard.downloads[0].raw, raw);
  assert.equal(storage.get(key), raw);
  assert.deepEqual({ ...dashboard.api.stateFor("F-001") }, beforeState);
  assert.match(dashboard.downloads[0].name, /rejected|unread|recovery/i);

  dashboard.api.updateState("F-001", { note: "must remain memory-only" });
  assert.equal(storage.get(key), raw, "recovery download must not unlock ordinary writes");
  assert.equal(recovery.hidden, false);

  dashboard.api.setCurrent("F-001");
  dashboard.element("answerInput").value = "조치 결론: 수정\n기존/수정 코드 비교:\n- old();\n+ CURRENT_MEMORY_DRAFT\n검증: 확인";
  dashboard.api.parseAnswer();
  assert.equal(storage.get(key), raw);

  dashboard.api.exportProgress();
  assert.equal(dashboard.downloads[1].data.schemaVersion, "1.0");
  assert.equal(dashboard.downloads[1].data.draftResults["F-001"].result.resultCodeDiff, "- old();\n+ CURRENT_MEMORY_DRAFT\n");
  assert.doesNotMatch(dashboard.downloads[1].raw, /ONLY_IN_REJECTED_RAW/);
});

test("the rejected-storage recovery action stays hidden without a rejected current payload", () => {
  const dashboard = loadDashboard({ bootstrap: true });
  assert.equal(dashboard.element("exportRejectedStorage").hidden, true);
});

test("a validated explicit import replaces and unlocks a rejected current-key envelope", () => {
  const key = 'sast-toolkit-progress:v2:"project-A"';
  const invalid = result({ diff: "RECOVER_ME" });
  invalid.sequence = "wrong-type";
  const raw = JSON.stringify({
    ...backup({ "F-001": item() }),
    draftResults: { "F-001": draft(invalid) },
  });
  const storage = new Map([[key, raw]]);
  const dashboard = loadDashboard({ storage, bootstrap: true });
  assert.equal(dashboard.element("exportRejectedStorage").hidden, false);

  assert.equal(dashboard.api.importProgressData({
    ...backup({ "F-001": item("analyzed", "needs-review", "recovered", DAY_3) }),
    draftResults: { "F-001": draft(result({ diff: "VALID_RECOVERY", updatedAt: DAY_3 }), DAY_3) },
  }), 1);
  assert.doesNotMatch(storage.get(key), /RECOVER_ME/);
  assert.match(storage.get(key), /VALID_RECOVERY/);
  assert.equal(dashboard.element("exportRejectedStorage").hidden, true);
  dashboard.api.updateState("F-001", { note: "save after recovery" });
  assert.match(storage.get(key), /save after recovery/);
});

test("a failed browser write leaves the previous complete envelope recoverable", () => {
  const storage = new Map();
  const first = loadDashboard({ storage });
  first.api.setCurrent("F-001");
  first.element("answerInput").value = "조치 결론: 수정\n기존/수정 코드 비교:\n- old();\n+ good();\n검증: 확인";
  first.api.parseAnswer();
  const before = Array.from(storage.entries());
  storage.set = () => { throw new Error("Quota exceeded"); };
  first.element("answerInput").value = "조치 결론: 수정\n기존/수정 코드 비교:\n- old();\n+ incomplete();\n검증: 확인";
  first.api.parseAnswer();
  assert.deepEqual(Array.from(storage.entries()), before);
  assert.match(first.element("localSaveStatus").textContent, /실패|못했/);
  assert.match(first.element("answerMessage").textContent, /현재 화면|백업/);
  assert.equal(first.element("answerMessage").classList.contains("warning"), true);
  assert.deepEqual(
    { ...first.api.resultProvenance("F-001") },
    { storage: "브라우저 초안: 현재 화면에만 있음 · 저장 실패", file: "정본 대조: 반영 대기" },
  );

  const recovered = loadDashboard({ storage });
  recovered.api.setCurrent("F-001");
  recovered.api.exportCurrentResult();
  assert.equal(recovered.downloads[0].data.resultCodeDiff, "- old();\n+ good();\n");
});

test("enum fields require primitive strings and own enum members", () => {
  const mutations = [
    (value) => { value.items["F-001"].workflowStatus = ["verified"]; },
    (value) => { value.items["F-001"].conclusion = "constructor"; },
    (value) => { value.draftResults["F-001"].result.workflowStatus = ["verified"]; },
    (value) => { value.draftResults["F-001"].result.conclusion = "constructor"; },
    (value) => { value.draftResults["F-001"].result.verification.status = "constructor"; },
    (value) => { value.draftResults["F-001"].result.verification.method = ["unit-test"]; },
  ];
  for (const mutate of mutations) {
    const dashboard = loadDashboard();
    const value = {
      ...backup({ "F-001": item() }),
      draftResults: { "F-001": draft(result()) },
    };
    mutate(value);
    assert.throws(() => dashboard.api.importProgressData(value), /진행상태|결론|초안|검증|형식/i);
    assert.equal(dashboard.storage.size, 0);
    assert.equal(dashboard.api.stateFor("F-001").workflowStatus, "todo");
  }
});

test("a newer browser draft remains pending while a newer canonical file wins freshness", () => {
  const storage = new Map();
  const envelope = {
    ...backup({ "F-001": item("change-complete", "fix", "draft", DAY_3) }),
    draftResults: { "F-001": draft(result({ diff: "- old();\n+ draft();\n", updatedAt: DAY_3 }), DAY_3) },
  };
  storage.set('sast-toolkit-progress:v2:"project-A"', JSON.stringify(envelope));

  const draftWins = loadDashboard({ storage, fileResults: { "F-001": result({ diff: "- old();\n+ file();\n", updatedAt: DAY_2 }) } });
  draftWins.api.setCurrent("F-001");
  draftWins.api.exportCurrentResult();
  assert.equal(draftWins.downloads[0].data.resultCodeDiff, "- old();\n+ draft();\n");

  const fileWins = loadDashboard({ storage, fileResults: { "F-001": result({ diff: "- old();\n+ canonical();\n", updatedAt: "2026-09-04T00:00:00Z" }) } });
  fileWins.api.setCurrent("F-001");
  fileWins.api.exportCurrentResult();
  assert.equal(fileWins.downloads[0].data.resultCodeDiff, "- old();\n+ canonical();\n");
});

test("importing a draft never promotes workflow or verification", () => {
  const dashboard = loadDashboard();
  const claimed = result({ workflowStatus: "verified", updatedAt: DAY_3 });
  claimed.verification = { status: "passed", commands: ["test"], results: ["ok"], limitations: [], verifiedAt: DAY_3 };
  dashboard.api.importProgressData({
    ...backup({ "F-001": item("todo", "unreviewed", "", DAY_3) }),
    draftResults: { "F-001": draft(claimed, DAY_3) },
  });
  assert.equal(dashboard.api.stateFor("F-001").workflowStatus, "todo");
  dashboard.api.setCurrent("F-001");
  dashboard.api.exportCurrentResult();
  assert.equal(dashboard.downloads[0].data.verification.status, "passed");
});

test("result provenance distinguishes browser-only, pending, and matching canonical data", () => {
  const browserOnly = loadDashboard();
  browserOnly.api.importProgressData({
    ...backup({ "F-001": item("change-complete", "fix", "", DAY_2) }),
    draftResults: { "F-001": draft(result(), DAY_3) },
  });
  assert.deepEqual(
    { ...browserOnly.api.resultProvenance("F-001") },
    { storage: "브라우저 초안: 저장됨", file: "정본 대조: 반영 대기" },
  );

  const storage = new Map();
  storage.set('sast-toolkit-progress:v2:"project-A"', JSON.stringify({
    ...backup({ "F-001": item("change-complete", "fix", "", DAY_2) }),
    draftResults: { "F-001": draft(result(), DAY_3) },
  }));
  const matching = loadDashboard({ storage, fileResults: { "F-001": result() } });
  assert.deepEqual(
    { ...matching.api.resultProvenance("F-001") },
    { storage: "브라우저 초안: 저장됨", file: "정본 대조: 내용 일치" },
  );
});

test("an identical older draft import does not roll back its saved timestamp", () => {
  const current = result({ updatedAt: DAY_2 });
  const dashboard = loadDashboard();
  dashboard.api.importProgressData({
    ...backup({ "F-001": item("change-complete", "fix", "", DAY_2) }),
    draftResults: { "F-001": draft(current, DAY_3) },
  });
  dashboard.api.importProgressData({
    ...backup({ "F-001": item("change-complete", "fix", "", DAY_2) }),
    draftResults: { "F-001": draft(current, DAY_1) },
  });
  dashboard.api.exportProgress();
  assert.equal(dashboard.downloads[0].data.draftResults["F-001"].savedAt, DAY_3);
});

test("an entirely stale import reports retained records rather than applied records", () => {
  const dashboard = loadDashboard();
  dashboard.api.importProgressData({
    ...backup({ "F-001": item("change-complete", "fix", "latest", DAY_3) }),
    draftResults: { "F-001": draft(result({ diff: "NEW", updatedAt: DAY_3 }), DAY_3) },
  });
  const applied = dashboard.api.importProgressData({
    ...backup({ "F-001": item("analyzed", "needs-review", "old", DAY_1) }),
    draftResults: { "F-001": draft(result({ diff: "OLD", updatedAt: DAY_1 }), DAY_1) },
  });
  assert.equal(applied, 0);
  assert.deepEqual({ ...dashboard.api.importAccounting() }, {
    statesApplied: 0, statesUnchanged: 0, statesRetained: 1,
    draftsApplied: 0, draftsUnchanged: 0, draftsRetained: 1,
    ignoredStates: 0,
  });
});

test("the import event reports mixed applied, unchanged, retained, and unknown outcomes", () => {
  const dashboard = loadDashboard({ findingCount: 3 });
  const sameState = item("analyzed", "needs-review", "same", DAY_2);
  const sameDraft = draft(result({ id: "F-002", diff: "SAME", updatedAt: DAY_2 }), DAY_2);
  dashboard.api.importProgressData({
    ...backup({
      "F-001": item("change-complete", "fix", "latest", DAY_3),
      "F-002": sameState,
      "F-003": item("todo", "unreviewed", "old", DAY_1),
    }),
    draftResults: {
      "F-001": draft(result({ diff: "NEW", updatedAt: DAY_3 }), DAY_3),
      "F-002": sameDraft,
      "F-003": draft(result({ id: "F-003", diff: "OLD", updatedAt: DAY_1 }), DAY_1),
    },
  });
  dashboard.api.bindEvents();
  const input = dashboard.element("progressFile");
  input.files = [{ text: JSON.stringify({
    ...backup({
      "F-001": item("analyzed", "needs-review", "stale", DAY_1),
      "F-002": sameState,
      "F-003": item("change-complete", "fix", "new", DAY_3),
      "UNKNOWN": item(),
    }),
    draftResults: {
      "F-001": draft(result({ diff: "STALE", updatedAt: DAY_1 }), DAY_1),
      "F-002": sameDraft,
      "F-003": draft(result({ id: "F-003", diff: "NEW", updatedAt: DAY_3 }), DAY_3),
    },
  }) }];
  input.listeners.change({ target: input });

  assert.deepEqual({ ...dashboard.api.importAccounting() }, {
    statesApplied: 1, statesUnchanged: 1, statesRetained: 1,
    draftsApplied: 1, draftsUnchanged: 1, draftsRetained: 1,
    ignoredStates: 1,
  });
  assert.match(dashboard.element("toast").textContent, /적용 1/);
  assert.match(dashboard.element("toast").textContent, /동일 1/);
  assert.match(dashboard.element("toast").textContent, /현재 값 유지 1/);
  assert.match(dashboard.element("toast").textContent, /알 수 없는 상태 ID 1/);
});

test("a foreign workspace backup cannot change or persist an overlapping finding", () => {
  const dashboard = loadDashboard({ fileItems: { "F-001": item() } });
  assert.throws(() => dashboard.api.importProgressData(backup({
    "F-001": item("verified", "false-positive", "Another project's conclusion", DAY_2),
  }, "project-B")), /workspace|프로젝트|차수/i);
  assert.equal(dashboard.api.stateFor("F-001").workflowStatus, "todo");
  assert.equal(dashboard.storage.size, 0);
});

test("an unsupported backup version is rejected without changing state", () => {
  const dashboard = loadDashboard();
  assert.throws(() => dashboard.api.importProgressData(backup({ "F-001": item("verified") }, "project-A", "2.0")), /schemaVersion|버전/i);
  assert.equal(dashboard.api.stateFor("F-001").workflowStatus, "todo");
  assert.equal(dashboard.storage.size, 0);
});

test("unidentified legacy backups require reconciliation instead of automatic import", () => {
  for (const legacy of [
    [{ id: "F-001", ...item("verified") }],
    { "F-001": item("verified") },
    { items: { "F-001": item("verified") } },
  ]) {
    const dashboard = loadDashboard();
    assert.throws(() => dashboard.api.importProgressData(legacy), /workspaceId|식별|이전|구형/i);
    assert.equal(dashboard.storage.size, 0);
  }
});

test("malformed backup records are rejected atomically instead of normalized into defaults", () => {
  for (const items of [[], null, { "F-001": null }, { "F-001": { ...item(), workflowStatus: "done" } }]) {
    const dashboard = loadDashboard();
    assert.throws(() => dashboard.api.importProgressData(backup(items)), /items|항목|진행상태/i);
    assert.equal(dashboard.storage.size, 0);
  }
});

test("a matching valid backup imports known IDs and exports a compatible envelope", () => {
  const dashboard = loadDashboard();
  const count = dashboard.api.importProgressData(backup({
    "F-001": item("analyzed", "needs-review", "Review the call site", DAY_2),
    "OTHER-ID": item(),
  }));
  assert.equal(count, 1);
  dashboard.api.exportProgress();
  assert.equal(dashboard.downloads[0].data.workspaceId, "project-A");
  assert.equal(dashboard.downloads[0].data.schemaVersion, "1.0");
  assert.deepEqual(dashboard.downloads[0].data.items, {
    "F-001": item("analyzed", "needs-review", "Review the call site", DAY_2),
  });
});

test("distinct Unicode workspace IDs keep independent browser state", () => {
  const storage = new Map();
  const first = loadDashboard({ workspaceId: "고객관리-1차", storage });
  first.api.updateState("F-001", { workflowStatus: "verified", conclusion: "false-positive" });
  const second = loadDashboard({ workspaceId: "재무관리-1차", storage });
  assert.equal(second.api.stateFor("F-001").workflowStatus, "todo");
  second.api.updateState("F-001", { workflowStatus: "analyzed" });
  assert.equal(storage.size, 2);
  assert.equal(loadDashboard({ workspaceId: "고객관리-1차", storage }).api.stateFor("F-001").workflowStatus, "verified");
});

test("same-workspace legacy browser state migrates without deleting the old copy", () => {
  const legacyKey = "sast-toolkit-progress:1";
  const original = JSON.stringify(backup({ "F-001": item("analyzed") }, "고객관리-1차"));
  const storage = new Map([[legacyKey, original]]);
  const dashboard = loadDashboard({ workspaceId: "고객관리-1차", storage });
  assert.equal(dashboard.api.stateFor("F-001").workflowStatus, "analyzed");
  assert.equal(storage.size, 2);
  assert.equal(storage.get(legacyKey), original);
});

test("colliding legacy storage from another workspace is ignored and reported", () => {
  const original = JSON.stringify(backup({ "F-001": item("verified") }, "고객관리-1차"));
  const storage = new Map([["sast-toolkit-progress:1", original]]);
  const dashboard = loadDashboard({ workspaceId: "재무관리-1차", storage });
  assert.equal(dashboard.api.stateFor("F-001").workflowStatus, "todo");
  dashboard.api.renderSyncNotice();
  assert.equal(dashboard.element("syncNotice").hidden, false);
  assert.equal(storage.size, 1);
});

test("metadata-free legacy browser state is preserved but not migrated", () => {
  const original = JSON.stringify({ items: { "F-001": item("verified") } });
  const storage = new Map([["sast-toolkit-progress:project-A", original]]);
  const dashboard = loadDashboard({ storage });
  assert.equal(dashboard.api.stateFor("F-001").workflowStatus, "todo");
  assert.equal(storage.size, 1);
});

test("current storage also rejects a mismatched workspace payload", () => {
  const storage = new Map();
  loadDashboard({ storage }).api.updateState("F-001", { workflowStatus: "analyzed" });
  const key = Array.from(storage.keys())[0];
  const foreign = JSON.stringify(backup({ "F-001": item("verified") }, "project-B"));
  storage.set(key, foreign);
  const dashboard = loadDashboard({ storage });
  assert.equal(dashboard.api.stateFor("F-001").workflowStatus, "todo");
  assert.equal(storage.get(key), foreign);
});

test("an identical older backup cannot roll the timestamp back and reopen older decisions", () => {
  const latest = item("deferred", "needs-review", "Retest needed", DAY_3);
  const dashboard = loadDashboard({ fileItems: { "F-001": latest } });
  dashboard.api.importProgressData(backup({ "F-001": { ...latest, updatedAt: DAY_1 } }));
  assert.equal(dashboard.api.stateFor("F-001").updatedAt, DAY_3);
  dashboard.api.importProgressData(backup({ "F-001": item("verified", "fix", "Old test passed", DAY_2) }));
  assert.equal(dashboard.api.stateFor("F-001").workflowStatus, "deferred");
});

test("an identical backup without a timestamp retains the current valid timestamp", () => {
  const latest = item("analyzed", "needs-review", "Read the caller", DAY_3);
  const dashboard = loadDashboard({ fileItems: { "F-001": latest } });
  dashboard.api.importProgressData(backup({ "F-001": { ...latest, updatedAt: null } }));
  assert.equal(dashboard.api.stateFor("F-001").updatedAt, DAY_3);
});

test("a newer timestamp and a newer explicit downgrade still win", () => {
  const verified = item("verified", "fix", "Passed", DAY_1);
  const dashboard = loadDashboard({ fileItems: { "F-001": verified } });
  dashboard.api.importProgressData(backup({ "F-001": { ...verified, updatedAt: DAY_2 } }));
  assert.equal(dashboard.api.stateFor("F-001").updatedAt, DAY_2);
  dashboard.api.importProgressData(backup({ "F-001": item("deferred", "needs-review", "Regression", DAY_3) }));
  assert.equal(dashboard.api.stateFor("F-001").workflowStatus, "deferred");
});

test("answer extraction and result download preserve unified diff code byte for byte", () => {
  const code = "@@ -1,3 +1,3 @@\n-  return input;\n+  return sanitize(input);\n \tcontext();  \n\n";
  const dashboard = loadDashboard();
  dashboard.api.setCurrent("F-001");
  dashboard.element("answerInput").value = "조치 결론: 수정\n기존/수정 코드 비교:\n```diff\n" + code + "```\n검증: 테스트 통과";
  dashboard.api.parseAnswer();
  dashboard.api.exportCurrentResult();
  assert.equal(dashboard.downloads[0].data.resultCodeDiff, code);
});

test("section labels and backticks inside fenced code remain code", () => {
  const code = '  const text = "```";\n검증:\n  *pointer = value;\n';
  const dashboard = loadDashboard();
  dashboard.api.setCurrent("F-001");
  dashboard.element("answerInput").value = "조치 결론: 수정\n기존/수정 코드 비교:\n```text\n" + code + "```\n검증: 별도 검증";
  dashboard.api.parseAnswer();
  dashboard.api.exportCurrentResult();
  assert.equal(dashboard.downloads[0].data.resultCodeDiff, code);
  assert.deepEqual(dashboard.downloads[0].data.verification.results, ["별도 검증"]);
});

test("unfenced code preserves indentation and deletion prefixes", () => {
  const dashboard = loadDashboard();
  dashboard.api.setCurrent("F-001");
  dashboard.element("answerInput").value = "조치 결론: 수정\n기존/수정 코드 비교:\n  before();\n- removed();\n+ added();\n검증: 확인";
  dashboard.api.parseAnswer();
  dashboard.api.exportCurrentResult();
  assert.equal(dashboard.downloads[0].data.resultCodeDiff, "  before();\n- removed();\n+ added();\n");
});

test("code comparison preserves CRLF line endings from the answer", () => {
  const code = "-  before();\r\n+  after();\r\n";
  const dashboard = loadDashboard();
  dashboard.api.setCurrent("F-001");
  dashboard.element("answerInput").value = "조치 결론: 수정\r\n기존/수정 코드 비교:\r\n```diff\r\n" + code + "```\r\n검증: 확인";
  dashboard.api.parseAnswer();
  dashboard.api.exportCurrentResult();
  assert.equal(dashboard.downloads[0].data.resultCodeDiff, code);
});

test("a code section containing prose around fences does not silently discard that prose", () => {
  const comparison = "기존 코드와 비교:\n```diff\n- before();\n+ after();\n```\n이 변경은 입력 검사만 추가합니다.\n";
  const dashboard = loadDashboard();
  dashboard.api.setCurrent("F-001");
  dashboard.element("answerInput").value = "조치 결론: 수정\n기존/수정 코드 비교:\n" + comparison + "검증: 확인";
  dashboard.api.parseAnswer();
  dashboard.api.exportCurrentResult();
  assert.equal(dashboard.downloads[0].data.resultCodeDiff, comparison);
});

test("an answer wrapped in a text fence still extracts conclusion, reason and verification", () => {
  const dashboard = loadDashboard();
  dashboard.api.setCurrent("F-001");
  dashboard.element("answerInput").value = "```text\n조치 결론: 수정\n판단 이유: 입력 검사 누락\n검증: 테스트 통과\n```";
  dashboard.api.parseAnswer();
  dashboard.api.exportCurrentResult();
  const result = dashboard.downloads[0].data;
  assert.equal(result.conclusion, "fix");
  assert.equal(result.reason, "입력 검사 누락");
  assert.deepEqual(result.verification.results, ["테스트 통과"]);
});

test("an outer answer fence is removed without removing its inner diff fence contents", () => {
  const code = "-  before();\r\n+  after();\r\n";
  for (const outer of ["```", "````", "~~~"]) {
    const dashboard = loadDashboard();
    dashboard.api.setCurrent("F-001");
    dashboard.element("answerInput").value = outer + "text\r\n조치 결론: 수정\r\n기존/수정 코드 비교:\r\n```diff\r\n" + code + "```\r\n검증: 확인\r\n" + outer;
    dashboard.api.parseAnswer();
    dashboard.api.exportCurrentResult();
    assert.equal(dashboard.downloads[0].data.conclusion, "fix");
    assert.equal(dashboard.downloads[0].data.resultCodeDiff, code);
    assert.deepEqual(dashboard.downloads[0].data.verification.results, ["확인"]);
  }
});

test("unrecognized answers cannot replace an existing result or update browser state", () => {
  for (const answer of ["형식 없는 임의 텍스트", "검증: 테스트 통과", "조치 결론: 알 수 없음", "조치 결론:\n판단 이유: 아직 결론 없음"]) {
    const dashboard = loadDashboard();
    dashboard.api.setCurrent("F-001");
    dashboard.element("answerInput").value = "조치 결론: 오탐\n판단 이유: 호출부에서 입력 검증됨\n검증: 소스 대조";
    dashboard.api.parseAnswer();
    dashboard.api.exportCurrentResult();
    const previousResult = dashboard.downloads[0].data;
    const previousStorage = Array.from(dashboard.storage.entries());
    dashboard.element("answerInput").value = answer;
    dashboard.api.parseAnswer();
    dashboard.api.exportCurrentResult();
    assert.deepEqual(dashboard.downloads[1].data, previousResult);
    assert.deepEqual(Array.from(dashboard.storage.entries()), previousStorage);
    assert.match(dashboard.element("answerMessage").textContent, /결론|형식/);
    assert.equal(dashboard.element("answerMessage").classList.contains("warning"), true);
  }
});

test("copying an AI request does not advance or downgrade any workflow state", async () => {
  for (const workflowStatus of ["todo", "in-progress", "analyzed", "change-complete", "verified", "deferred"]) {
    const dashboard = loadDashboard({ fileItems: { "F-001": item(workflowStatus) } });
    dashboard.api.setCurrent("F-001");
    dashboard.api.bindEvents();
    await dashboard.element("copyTaskPrompt").listeners.click();
    assert.equal(dashboard.api.stateFor("F-001").workflowStatus, workflowStatus);
    assert.equal(dashboard.storage.size, 0);
  }
});

test("opening and closing details moves focus and blocks the background", () => {
  const dashboard = loadDashboard();
  const trigger = dashboard.element("finding-trigger");
  trigger.focus();
  dashboard.element("detailDrawer").inert = true;
  dashboard.api.openDetail("F-001");
  assert.equal(dashboard.active().id, "closeDrawer");
  assert.equal(dashboard.element("detailDrawer").inert, false);
  assert.equal(dashboard.element("appHeader").inert, true);
  assert.equal(dashboard.element("mainContent").inert, true);
  assert.equal(dashboard.element("body").classList.contains("drawer-open"), true);
  dashboard.api.closeDetail();
  assert.equal(dashboard.active(), trigger);
  assert.equal(dashboard.element("detailDrawer").inert, true);
  assert.equal(dashboard.element("appHeader").inert, false);
  assert.equal(dashboard.element("mainContent").inert, false);
  assert.equal(dashboard.element("body").classList.contains("drawer-open"), false);
});

test("detail close restores a replaced finding button or falls back to search", () => {
  for (const hasReplacement of [true, false]) {
    const dashboard = loadDashboard();
    const trigger = dashboard.element("old-trigger");
    trigger.focus();
    dashboard.api.openDetail("F-001");
    trigger.isConnected = false;
    const replacement = dashboard.element("new-trigger");
    replacement.dataset.findingId = "F-001";
    dashboard.select("button[data-finding-id]", hasReplacement ? [replacement] : []);
    dashboard.api.closeDetail();
    assert.equal(dashboard.active().id, hasReplacement ? "new-trigger" : "search");
  }
});

test("Tab is trapped inside details and Escape closes with focus restoration", () => {
  const dashboard = loadDashboard();
  const trigger = dashboard.element("finding-trigger");
  trigger.focus();
  dashboard.api.bindEvents();
  dashboard.api.openDetail("F-001");
  const drawer = dashboard.element("detailDrawer");
  const first = dashboard.element("closeDrawer");
  const last = dashboard.element("parseAnswer");
  drawer.appendChild(first);
  drawer.appendChild(last);
  drawer.focusable = [first, last];
  let prevented = 0;
  const key = (key, shiftKey = false) => dashboard.documentListeners.keydown({ key, shiftKey, preventDefault() { prevented += 1; } });
  last.focus();
  key("Tab");
  assert.equal(dashboard.active(), first);
  key("Tab", true);
  assert.equal(dashboard.active(), last);
  assert.equal(prevented, 2);
  key("Escape");
  assert.equal(dashboard.active(), trigger);
  assert.equal(drawer.inert, true);
});

test("sort and insight filters restart pagination at the first page", () => {
  for (const action of ["sort", "stat"]) {
    const dashboard = loadDashboard({ findingCount: 205 });
    const sort = dashboard.element("sort-sequence");
    sort.dataset.sort = "sequence";
    dashboard.select(".sort-button", [sort]);
    dashboard.element("pageSize").value = "100";
    dashboard.useTableRendering();
    dashboard.api.bindEvents();
    dashboard.element("nextPage").listeners.click();
    assert.equal(dashboard.element("pageInfo").textContent, "101–200 / 205건");
    if (action === "sort") sort.listeners.click();
    else {
      const stat = dashboard.element("risk-stat");
      stat.dataset.filterType = "risk";
      stat.dataset.filterValue = "high";
      dashboard.element("riskStats").listeners.click({ target: stat });
    }
    assert.equal(dashboard.element("pageInfo").textContent, "1–100 / 205건");
  }
});

test("metric selection and sort direction are exposed to assistive technology", () => {
  const dashboard = loadDashboard();
  const all = dashboard.element("metric-all");
  all.dataset.dashboardFilter = "all";
  const verified = dashboard.element("metric-verified");
  verified.dataset.dashboardFilter = "verified";
  dashboard.select("[data-dashboard-filter]", [all, verified]);
  const sort = dashboard.element("sort-sequence");
  sort.dataset.sort = "sequence";
  sort.appendChild(dashboard.element("sort-mark"));
  const heading = dashboard.element("sequence-heading");
  heading.appendChild(sort);
  dashboard.select(".sort-button", [sort]);
  dashboard.api.bindEvents();
  verified.listeners.click();
  dashboard.api.renderDashboardFilter();
  assert.equal(verified.getAttribute("aria-pressed"), "true");
  assert.equal(all.getAttribute("aria-pressed"), "false");
  dashboard.api.updateSortIndicators();
  assert.equal(heading.getAttribute("aria-sort"), "ascending");
  sort.listeners.click();
  dashboard.api.updateSortIndicators();
  assert.equal(heading.getAttribute("aria-sort"), "descending");
});

test("saving browser state provides persistent success and failure feedback", () => {
  const dashboard = loadDashboard();
  dashboard.api.updateState("F-001", { note: "Needs review" });
  assert.match(dashboard.element("localSaveStatus").textContent, /브라우저.*저장/);
  dashboard.storage.set = () => { throw new Error("Quota exceeded"); };
  dashboard.api.updateState("F-001", { note: "Not persisted" });
  assert.match(dashboard.element("localSaveStatus").textContent, /실패|못했/);
});

test("each table detail button has an accessible name identifying its finding", () => {
  const dashboard = loadDashboard();
  dashboard.element("pageSize").value = "100";
  dashboard.api.renderTable([{ id: "F-001", sequence: 1 }]);
  const row = dashboard.element("findingsBody").children[0];
  const detail = row.children[row.children.length - 1].children[0];
  assert.match(detail.getAttribute("aria-label") || "", /F-001/);
});

test("recommendation limits keep all eligible rows and exclude verified or deferred findings", () => {
  const dashboard = loadDashboard({ findingCount: 23, fileItems: {
    "F-001": item("verified", "fix"), "F-002": item("deferred"),
  } });
  dashboard.useRecommendationRendering();
  dashboard.api.bindEvents();
  const list = dashboard.element("recommendations");
  for (const [limit, count, lastId] of [["5", 5, "F-007"], ["10", 10, "F-012"], ["20", 20, "F-022"], ["all", 21, "F-023"]]) {
    dashboard.element("recommendationLimit").value = limit;
    dashboard.element("recommendationLimit").listeners.input();
    assert.equal(list.children.length, count);
    assert.equal(list.children[0].children.at(-1).dataset.findingId, "F-003");
    assert.equal(list.children.at(-1).children.at(-1).dataset.findingId, lastId);
  }
  assert.equal(dashboard.storage.size, 0, "changing display limits must not save workflow state");
});

test("unrelated table filtering and sorting preserve the recommendation scroll offset", () => {
  for (const action of ["filter", "sort"]) {
    const dashboard = loadDashboard({ findingCount: 50 });
    dashboard.useRecommendationRendering();
    dashboard.element("recommendationLimit").value = "all";
    const sort = dashboard.element("sort-sequence");
    sort.dataset.sort = "sequence";
    dashboard.select(".sort-button", [sort]);
    dashboard.api.bindEvents();
    dashboard.api.renderRecommendations();
    const list = dashboard.element("recommendations");
    list.scrollTop = 640;
    if (action === "filter") {
      dashboard.element("checkerFilter").value = "OTHER";
      dashboard.element("checkerFilter").listeners.input();
    } else sort.listeners.click();
    assert.equal(list.scrollTop, 640, action + " must not move the independent recommendation list");
    assert.equal(list.children.length, 50);
  }
});

test("changing recommendation count resets only its scroll while keeping table filters and page", () => {
  const dashboard = loadDashboard({ findingCount: 205 });
  dashboard.useRecommendationRendering();
  dashboard.useTableRendering();
  dashboard.element("recommendationLimit").value = "all";
  dashboard.element("pageSize").value = "100";
  dashboard.api.bindEvents();
  dashboard.element("nextPage").listeners.click();
  dashboard.element("checkerFilter").value = "KEEP";
  dashboard.element("recommendations").scrollTop = 920;
  dashboard.element("recommendationLimit").value = "20";
  dashboard.element("recommendationLimit").listeners.input();
  assert.equal(dashboard.element("recommendations").scrollTop, 0);
  assert.equal(dashboard.element("recommendations").children.length, 20);
  assert.equal(dashboard.element("checkerFilter").value, "KEEP");
  assert.equal(dashboard.element("pageInfo").textContent, "101–200 / 205건");
});

test("recommendation detail round trip restores its button and scroll after a state rerender", () => {
  const dashboard = loadDashboard({ findingCount: 50 });
  dashboard.useRecommendationRendering();
  dashboard.element("recommendationLimit").value = "all";
  dashboard.api.renderRecommendations();
  const list = dashboard.element("recommendations");
  list.scrollTop = 640;
  const trigger = list.children[12].children.at(-1);
  trigger.focus();
  dashboard.api.openDetail("F-013");
  dashboard.api.updateState("F-013", { workflowStatus: "analyzed" });
  const buttons = list.children.map((row) => row.children.at(-1));
  dashboard.select("button[data-finding-id]", buttons);
  dashboard.api.closeDetail();
  assert.equal(dashboard.active(), buttons[12]);
  assert.equal(dashboard.active().dataset.findingId, "F-013");
  assert.equal(list.scrollTop, 640);
});

test("an empty recommendation list resets scrolling and shows the empty explanation", () => {
  const dashboard = loadDashboard();
  dashboard.useRecommendationRendering();
  dashboard.api.renderRecommendations();
  const list = dashboard.element("recommendations");
  list.scrollTop = 20;
  dashboard.api.updateState("F-001", { workflowStatus: "deferred" });
  assert.equal(list.scrollTop, 0);
  assert.equal(list.children.length, 1);
  assert.match(list.children[0].textContent, /추천할 진행 대상이 없습니다/);
});
