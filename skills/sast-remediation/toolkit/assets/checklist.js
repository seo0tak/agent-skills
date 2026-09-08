(function () {
  "use strict";

  var toolkitData = window.SAST_TOOLKIT_DATA || {};
  var inputValidation = toolkitData.inputValidation || { status: "unreviewed", blockers: [] };
  var profile = toolkitData.projectProfile || {};
  var findings = Array.isArray(toolkitData.findings) ? toolkitData.findings : [];
  var checkerGuides = toolkitData.checkerGuides || {};
  var fileProgress = toolkitData.progress || { schemaVersion: "1.0", workspaceId: "uninitialized", items: {} };

  window.SAST_ITEM_GUIDES = window.SAST_ITEM_GUIDES || {};
  window.SAST_ITEM_RESULTS = window.SAST_ITEM_RESULTS || {};

  var WORKFLOW = {
    "todo": "미착수",
    "in-progress": "진행중",
    "analyzed": "분석완료",
    "change-complete": "변경완료",
    "verified": "검증완료",
    "deferred": "보류"
  };
  var WORKFLOW_RANK = {
    "todo": 0,
    "in-progress": 1,
    "analyzed": 2,
    "change-complete": 3,
    "verified": 4,
    "deferred": 1
  };
  var CONCLUSION = {
    "unreviewed": "미판정",
    "fix": "수정",
    "false-positive": "오탐",
    "operations": "운영 설정",
    "exception": "예외처리",
    "needs-review": "추가 검토"
  };
  var MAPPING = {
    "unreviewed": "미대조",
    "exact": "일치",
    "relocated": "위치 이동",
    "changed": "코드 변경",
    "not-found": "미발견",
    "generated-or-external": "생성/외부"
  };
  var MAPPING_PRIORITY = {
    "exact": 0,
    "relocated": 1,
    "changed": 2,
    "unreviewed": 3,
    "not-found": 4,
    "generated-or-external": 5
  };
  var READINESS = {
    "unreviewed": {
      title: "작업 시작 조건 확인 전",
      badge: "사전 점검 전",
      message: "현재 프로젝트와 입력 보고서의 적합성을 먼저 확인해야 합니다.",
      className: ""
    },
    "mechanical-ready": {
      title: "파일 검사 통과, 내용 대조 필요",
      badge: "보고서 대조 필요",
      message: "파일은 유효하지만 프로젝트와 검사 차수의 일치 여부가 아직 확정되지 않았습니다.",
      className: ""
    },
    "ready": {
      title: "작업 시작 가능",
      badge: "입력 검증 완료",
      message: "현재 프로젝트와 두 보고서의 적합성이 확인되었습니다.",
      className: "ready"
    },
    "blocked": {
      title: "작업 시작 차단",
      badge: "입력 확인 필요",
      message: "입력 자료를 바로잡거나 일치 근거를 확인한 뒤 다시 점검해야 합니다.",
      className: "blocked"
    }
  };

  var currentFindingId = null;
  var dashboardFilter = "all";
  var sortState = { key: "sequence", direction: "asc" };
  var itemGuideCache = Object.assign({}, window.SAST_ITEM_GUIDES);
  var resultCache = Object.assign({}, window.SAST_ITEM_RESULTS);
  var pageIndex = 0;
  var toastTimer = null;

  function byId(id) { return document.getElementById(id); }
  function asString(value) { return value == null ? "" : String(value); }
  function validKey(map, value, fallback) { return Object.prototype.hasOwnProperty.call(map, value) ? value : fallback; }
  function nowIso() { return new Date().toISOString(); }
  function safeFilePart(value) { return asString(value || "workspace").replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "workspace"; }
  function findingById(id) { return findings.find(function (item) { return asString(item.id) === asString(id); }) || null; }
  function sourceMapping(item) { return item && item.sourceMapping ? item.sourceMapping : {}; }
  function reportedLocation(item) { return item && item.location ? item.location : {}; }
  function risk(item) { return item && item.risk ? item.risk : { level: "unknown", label: "Unknown", rank: 0 }; }
  function impact(item) { return item && item.impact ? item.impact : { level: "unknown", label: "Unknown", rank: 0 }; }
  function checker(item) { return item && item.checker ? item.checker : { code: "", name: "", category: "" }; }
  function gateReady() { return inputValidation.status === "ready"; }

  var workspaceId = profile.workspaceId || (profile.report && profile.report.id) || "uninitialized";
  var storageKey = "sast-toolkit-progress:" + safeFilePart(workspaceId);

  function normalizeStateItem(item) {
    var value = item && typeof item === "object" ? item : {};
    return {
      workflowStatus: validKey(WORKFLOW, value.workflowStatus, "todo"),
      conclusion: validKey(CONCLUSION, value.conclusion, "unreviewed"),
      note: asString(value.note),
      updatedAt: value.updatedAt || null
    };
  }

  function loadLocalProgress() {
    try {
      var parsed = JSON.parse(localStorage.getItem(storageKey) || "{}");
      return parsed && parsed.items && typeof parsed.items === "object" ? parsed : { items: {} };
    } catch (error) {
      return { items: {} };
    }
  }

  function stateItemsEqual(a, b) {
    return a.workflowStatus === b.workflowStatus && a.conclusion === b.conclusion && a.note === b.note;
  }

  function timestampOf(item) {
    var value = item && item.updatedAt ? Date.parse(item.updatedAt) : NaN;
    return isNaN(value) ? null : value;
  }

  // 병합 규칙: 항목별 updatedAt이 더 최신인 쪽이 이긴다.
  // 타임스탬프를 비교할 수 없으면 이전 동작(incoming 우선, verified 강등
  // 금지)을 유지한다. 값이 다른 항목은 방향별로 충돌 건수를 집계한다.
  function mergeStateItems(baseItems, incomingItems, preserveVerified) {
    var merged = {};
    var conflicts = { baseNewer: 0, incomingNewer: 0 };
    Object.keys(baseItems || {}).forEach(function (id) {
      merged[id] = normalizeStateItem(baseItems[id]);
    });
    Object.keys(incomingItems || {}).forEach(function (id) {
      var hasBase = Object.prototype.hasOwnProperty.call(merged, id);
      var current = normalizeStateItem(merged[id]);
      var incoming = normalizeStateItem(incomingItems[id]);
      if (!hasBase) {
        merged[id] = incoming;
        return;
      }
      if (stateItemsEqual(current, incoming)) {
        merged[id] = Object.assign({}, current, incoming);
        return;
      }
      var baseTime = timestampOf(current);
      var incomingTime = timestampOf(incoming);
      if (baseTime !== null && incomingTime !== null && baseTime > incomingTime) {
        conflicts.baseNewer += 1;
        return;
      }
      if (baseTime !== null && incomingTime !== null && incomingTime > baseTime) {
        conflicts.incomingNewer += 1;
      }
      if (preserveVerified && current.workflowStatus === "verified" && incoming.workflowStatus !== "verified"
        && !(baseTime !== null && incomingTime !== null && incomingTime > baseTime)) {
        incoming.workflowStatus = "verified";
      }
      merged[id] = Object.assign({}, current, incoming);
    });
    return { items: merged, conflicts: conflicts };
  }

  var localProgress = loadLocalProgress();
  var initialMerge = mergeStateItems(fileProgress.items || {}, localProgress.items || {}, true);
  var state = initialMerge.items;
  var mergeConflicts = initialMerge.conflicts;

  function renderSyncNotice() {
    var notice = byId("syncNotice");
    if (!notice) { return; }
    var messages = [];
    if (mergeConflicts.baseNewer > 0) {
      messages.push(
        "파일 진행상태(data/progress.js)가 브라우저 저장본보다 최신인 항목 "
        + mergeConflicts.baseNewer + "건을 파일 기준으로 반영했습니다."
      );
    }
    if (mergeConflicts.incomingNewer > 0) {
      messages.push(
        "브라우저에만 있는 변경 " + mergeConflicts.incomingNewer
        + "건이 파일에 반영되지 않았습니다. [상태 백업]으로 내려받아 data/progress.json을 갱신하세요."
      );
    }
    if (messages.length === 0) {
      notice.hidden = true;
      notice.textContent = "";
      return;
    }
    notice.hidden = false;
    notice.textContent = messages.join(" ");
  }

  function stateFor(id) {
    return normalizeStateItem(state[asString(id)]);
  }

  function saveState() {
    var payload = {
      schemaVersion: "1.0",
      workspaceId: workspaceId,
      updatedAt: nowIso(),
      items: state
    };
    try {
      localStorage.setItem(storageKey, JSON.stringify(payload));
    } catch (error) {
      showToast("브라우저에 진행상태를 저장하지 못했습니다.", "warning");
    }
  }

  function updateState(id, patch) {
    var key = asString(id);
    state[key] = Object.assign({}, stateFor(key), patch || {}, { updatedAt: nowIso() });
    saveState();
    render();
  }

  function showToast(message, kind) {
    var toast = byId("toast");
    toast.textContent = message;
    toast.style.borderColor = kind === "warning" ? "#efd19e" : "#b9cff0";
    toast.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toast.classList.remove("show"); }, 2600);
  }

  function makeChip(text, className) {
    var span = document.createElement("span");
    span.className = "chip " + asString(className);
    span.textContent = asString(text);
    return span;
  }

  function addOption(select, value, label) {
    var option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    select.appendChild(option);
  }

  function initializeHeader() {
    var report = profile.report || {};
    var projectName = profile.projectName || "프로젝트 미분석";
    var reportId = report.id || "리포트 미등록";
    byId("projectBadge").textContent = projectName;
    byId("reportBadge").textContent = reportId;
    var readiness = READINESS[inputValidation.status] || READINESS.unreviewed;
    byId("inputBadge").textContent = readiness.badge;
    document.title = projectName && reportId ? projectName + " SAST 체크리스트" : "SAST 취약점 체크리스트";
  }

  function initializeReadiness() {
    var readiness = READINESS[inputValidation.status] || READINESS.unreviewed;
    var panel = byId("readinessPanel");
    panel.className = "readiness-band" + (readiness.className ? " " + readiness.className : "");
    setText("readinessTitle", readiness.title);
    setText(
      "readinessMessage",
      inputValidation.matching && inputValidation.matching.reason
        ? inputValidation.matching.reason
        : readiness.message
    );
    var blockers = Array.isArray(inputValidation.blockers) ? inputValidation.blockers : [];
    var blockerList = byId("readinessBlockers");
    blockerList.textContent = "";
    if (!gateReady() && !blockers.length) {
      blockers = ["프로젝트와 보고서 내용을 대조해 최종 게이트를 통과해야 합니다."];
    }
    blockers.forEach(function (message) {
      var item = document.createElement("li");
      item.textContent = message;
      blockerList.appendChild(item);
    });

    ["detailWorkflow", "detailConclusion", "detailNote", "copyTaskPrompt", "parseAnswer"].forEach(function (id) {
      byId(id).disabled = !gateReady();
    });
  }

  function initializeFilters() {
    var checkerSelect = byId("checkerFilter");
    var checkerCounts = {};
    findings.forEach(function (item) {
      var code = checker(item).code;
      if (code) checkerCounts[code] = (checkerCounts[code] || 0) + 1;
    });
    Array.from(new Set(findings.map(function (item) { return checker(item).code; }).filter(Boolean))).sort().forEach(function (code) {
      var guide = checkerGuides[code] || {};
      var label = guide.name ? code + " - " + guide.name : code;
      addOption(checkerSelect, code, label + " (" + (checkerCounts[code] || 0) + ")");
    });

    var languageCounts = {};
    findings.forEach(function (item) {
      var lang = asString(item.language).trim();
      if (lang) languageCounts[lang] = (languageCounts[lang] || 0) + 1;
    });
    Object.keys(languageCounts).sort(function (a, b) { return languageCounts[b] - languageCounts[a]; }).forEach(function (lang) {
      addOption(byId("languageFilter"), lang, lang + " (" + languageCounts[lang] + ")");
    });

    var riskValues = {};
    findings.forEach(function (item) {
      var value = risk(item);
      riskValues[value.level] = value;
    });
    Object.keys(riskValues).sort(function (a, b) { return riskValues[b].rank - riskValues[a].rank; }).forEach(function (level) {
      addOption(byId("riskFilter"), level, riskValues[level].label || level);
    });

    Object.keys(WORKFLOW).forEach(function (value) { addOption(byId("workflowFilter"), value, WORKFLOW[value]); });
    Object.keys(CONCLUSION).forEach(function (value) { addOption(byId("conclusionFilter"), value, CONCLUSION[value]); });
    Object.keys(MAPPING).forEach(function (value) { addOption(byId("mappingFilter"), value, MAPPING[value]); });

    Object.keys(WORKFLOW).forEach(function (value) { addOption(byId("detailWorkflow"), value, WORKFLOW[value]); });
    Object.keys(CONCLUSION).forEach(function (value) { addOption(byId("detailConclusion"), value, CONCLUSION[value]); });
  }

  function highRisk(item) {
    return risk(item).rank >= 60 || ["critical", "very-high", "high"].indexOf(risk(item).level) >= 0;
  }

  function dashboardMatch(item) {
    var itemState = stateFor(item.id);
    if (dashboardFilter === "all") return true;
    if (dashboardFilter === "high-pending") return highRisk(item) && itemState.workflowStatus !== "verified" && itemState.workflowStatus !== "deferred";
    if (dashboardFilter === "analyzed") return itemState.workflowStatus === "analyzed";
    if (dashboardFilter === "change-complete") return itemState.workflowStatus === "change-complete";
    if (dashboardFilter === "verified") return itemState.workflowStatus === "verified";
    if (dashboardFilter === "false-positive") return itemState.conclusion === "false-positive";
    return true;
  }

  function filteredFindings() {
    var term = byId("search").value.trim().toLowerCase();
    var checkerValue = byId("checkerFilter").value;
    var riskValue = byId("riskFilter").value;
    var workflowValue = byId("workflowFilter").value;
    var conclusionValue = byId("conclusionFilter").value;
    var mappingValue = byId("mappingFilter").value;
    var languageValue = byId("languageFilter").value;

    return findings.filter(function (item) {
      var itemState = stateFor(item.id);
      var mapping = sourceMapping(item);
      var report = item.report || {};
      var blob = [
        item.sequence, item.id, risk(item).label, impact(item).label,
        checker(item).code, checker(item).name, checker(item).category,
        reportedLocation(item).reportedFile, reportedLocation(item).reportedFunction,
        mapping.currentFile, mapping.currentFunction, mapping.evidence,
        report.description, report.detectedCode, itemState.note
      ].join(" ").toLowerCase();

      return dashboardMatch(item) &&
        (!term || blob.indexOf(term) >= 0) &&
        (!checkerValue || checker(item).code === checkerValue) &&
        (!riskValue || risk(item).level === riskValue) &&
        (!workflowValue || itemState.workflowStatus === workflowValue) &&
        (!conclusionValue || itemState.conclusion === conclusionValue) &&
        (!mappingValue || mapping.status === mappingValue) &&
        (!languageValue || asString(item.language).trim() === languageValue);
    });
  }

  function compareFindings(a, b) {
    var direction = sortState.direction === "asc" ? 1 : -1;
    var av;
    var bv;
    if (sortState.key === "risk") {
      av = risk(a).rank;
      bv = risk(b).rank;
    } else if (sortState.key === "checker") {
      av = checker(a).code;
      bv = checker(b).code;
    } else if (sortState.key === "file") {
      av = sourceMapping(a).currentFile || reportedLocation(a).reportedFile;
      bv = sourceMapping(b).currentFile || reportedLocation(b).reportedFile;
    } else {
      av = a[sortState.key];
      bv = b[sortState.key];
    }
    if (typeof av === "number" && typeof bv === "number") return (av - bv) * direction;
    return asString(av).localeCompare(asString(bv), undefined, { numeric: true }) * direction;
  }

  function setText(id, value) { byId(id).textContent = asString(value); }

  function renderSummary(filtered) {
    var allStates = findings.map(function (item) { return stateFor(item.id); });
    var verified = allStates.filter(function (item) { return item.workflowStatus === "verified"; }).length;
    setText("totalCount", findings.length);
    setText("shownCount", filtered.length);
    setText("highPendingCount", findings.filter(function (item) {
      var itemState = stateFor(item.id);
      return highRisk(item) && itemState.workflowStatus !== "verified" && itemState.workflowStatus !== "deferred";
    }).length);
    setText("analyzedCount", allStates.filter(function (item) { return item.workflowStatus === "analyzed"; }).length);
    setText("changeCompleteCount", allStates.filter(function (item) { return item.workflowStatus === "change-complete"; }).length);
    setText("verifiedCount", verified);
    setText("falsePositiveCount", allStates.filter(function (item) { return item.conclusion === "false-positive"; }).length);
    var rate = findings.length ? Math.round((verified / findings.length) * 100) : 0;
    setText("verificationRate", rate + "%");
    byId("verificationBar").style.width = rate + "%";
  }

  function countBy(items, keyFunction) {
    return items.reduce(function (counts, item) {
      var key = keyFunction(item) || "unknown";
      counts[key] = (counts[key] || 0) + 1;
      return counts;
    }, {});
  }

  function renderStats(containerId, counts, labels, filterType) {
    var container = byId(containerId);
    container.textContent = "";
    var entries = Object.keys(counts).map(function (key) { return { key: key, count: counts[key] }; });
    entries.sort(function (a, b) { return b.count - a.count || asString(labels[a.key] || a.key).localeCompare(asString(labels[b.key] || b.key)); });
    var max = entries.length ? entries[0].count : 1;
    entries.forEach(function (entry) {
      var row = document.createElement("div");
      row.className = "stat-row";
      var button = document.createElement("button");
      button.type = "button";
      button.textContent = labels[entry.key] || entry.key;
      button.dataset.filterType = filterType;
      button.dataset.filterValue = entry.key;
      var track = document.createElement("div");
      track.className = "stat-track";
      var fill = document.createElement("div");
      fill.className = "stat-fill";
      fill.style.width = Math.round((entry.count / max) * 100) + "%";
      track.appendChild(fill);
      var count = document.createElement("span");
      count.className = "stat-count";
      count.textContent = entry.count;
      row.appendChild(button);
      row.appendChild(track);
      row.appendChild(count);
      container.appendChild(row);
    });
  }

  function renderInsights(filtered) {
    var riskLabels = {};
    filtered.forEach(function (item) { riskLabels[risk(item).level] = risk(item).label || risk(item).level; });
    renderStats("riskStats", countBy(filtered, function (item) { return risk(item).level; }), riskLabels, "risk");
    renderStats("conclusionStats", countBy(filtered, function (item) { return stateFor(item.id).conclusion; }), CONCLUSION, "conclusion");
    renderStats("mappingStats", countBy(filtered, function (item) { return sourceMapping(item).status || "unreviewed"; }), MAPPING, "mapping");
  }

  function recommendationCompare(a, b) {
    var riskDiff = risk(b).rank - risk(a).rank;
    if (riskDiff) return riskDiff;
    var impactDiff = impact(b).rank - impact(a).rank;
    if (impactDiff) return impactDiff;
    var statusA = sourceMapping(a).status;
    var statusB = sourceMapping(b).status;
    var priorityA = Object.prototype.hasOwnProperty.call(MAPPING_PRIORITY, statusA) ? MAPPING_PRIORITY[statusA] : 9;
    var priorityB = Object.prototype.hasOwnProperty.call(MAPPING_PRIORITY, statusB) ? MAPPING_PRIORITY[statusB] : 9;
    var mapDiff = priorityA - priorityB;
    if (mapDiff) return mapDiff;
    return Number(a.sequence || 0) - Number(b.sequence || 0);
  }

  function renderRecommendations() {
    var limitValue = byId("recommendationLimit").value;
    var candidates = findings.filter(function (item) {
      var value = stateFor(item.id).workflowStatus;
      return value !== "verified" && value !== "deferred";
    }).sort(recommendationCompare);
    if (limitValue !== "all") candidates = candidates.slice(0, Number(limitValue));

    var container = byId("recommendations");
    container.textContent = "";
    if (!candidates.length) {
      var empty = document.createElement("p");
      empty.textContent = "추천할 미처리 항목이 없습니다.";
      container.appendChild(empty);
      return;
    }
    candidates.forEach(function (item) {
      var row = document.createElement("div");
      row.className = "recommendation";
      var sequence = document.createElement("strong");
      sequence.textContent = "#" + item.sequence;
      row.appendChild(sequence);
      row.appendChild(makeChip(risk(item).label, risk(item).level));
      var mappingChip = makeChip(MAPPING[sourceMapping(item).status] || MAPPING.unreviewed, sourceMapping(item).status);
      mappingChip.classList.add("mapping-summary");
      row.appendChild(mappingChip);
      var main = document.createElement("div");
      main.className = "recommendation-main";
      var name = document.createElement("strong");
      name.textContent = checker(item).code + (checker(item).name ? " - " + checker(item).name : "");
      var file = document.createElement("code");
      file.textContent = sourceMapping(item).currentFile || reportedLocation(item).reportedFile || "-";
      main.appendChild(name);
      main.appendChild(file);
      row.appendChild(main);
      var button = document.createElement("button");
      button.type = "button";
      button.textContent = "상세";
      button.dataset.findingId = item.id;
      row.appendChild(button);
      container.appendChild(row);
    });
  }

  function appendCell(row, content, className) {
    var cell = document.createElement("td");
    if (className) cell.className = className;
    if (content instanceof Node) cell.appendChild(content);
    else cell.textContent = asString(content);
    row.appendChild(cell);
    return cell;
  }

  function renderTable(items) {
    var body = byId("findingsBody");
    body.textContent = "";
    var sizeValue = byId("pageSize") ? byId("pageSize").value : "all";
    var pageItems = items;
    var totalPages = 1;
    if (sizeValue !== "all") {
      var size = Number(sizeValue) || 200;
      totalPages = Math.max(1, Math.ceil(items.length / size));
      if (pageIndex >= totalPages) pageIndex = totalPages - 1;
      if (pageIndex < 0) pageIndex = 0;
      pageItems = items.slice(pageIndex * size, (pageIndex + 1) * size);
    } else {
      pageIndex = 0;
    }
    var pager = byId("pager");
    if (pager) {
      var start = items.length === 0 ? 0 : (sizeValue === "all" ? 1 : pageIndex * Number(sizeValue) + 1);
      var end = sizeValue === "all" ? items.length : Math.min(items.length, (pageIndex + 1) * Number(sizeValue));
      byId("pageInfo").textContent = items.length === 0 ? "0건" : start + "\u2013" + end + " / " + items.length + "\uAC74";
      byId("prevPage").disabled = pageIndex <= 0;
      byId("nextPage").disabled = pageIndex >= totalPages - 1;
      pager.classList.toggle("hidden", items.length === 0);
    }
    pageItems.forEach(function (item) {
      var itemState = stateFor(item.id);
      var mapping = sourceMapping(item);
      var row = document.createElement("tr");
      row.dataset.findingId = item.id;
      if (itemState.workflowStatus === "verified") row.classList.add("verified-row");
      appendCell(row, item.sequence);
      appendCell(row, item.id);
      appendCell(row, makeChip(risk(item).label, risk(item).level));
      appendCell(row, makeChip(impact(item).label, impact(item).level));
      var checkerCell = document.createElement("code");
      checkerCell.textContent = checker(item).code;
      checkerCell.title = checker(item).name || checker(item).code;
      appendCell(row, checkerCell);
      appendCell(row, mapping.currentFile || reportedLocation(item).reportedFile, "file-cell");
      appendCell(row, makeChip(MAPPING[mapping.status] || MAPPING.unreviewed, mapping.status));
      appendCell(row, makeChip(WORKFLOW[itemState.workflowStatus], itemState.workflowStatus));
      appendCell(row, makeChip(CONCLUSION[itemState.conclusion], itemState.conclusion));
      var detailButton = document.createElement("button");
      detailButton.type = "button";
      detailButton.className = "detail-button";
      detailButton.textContent = "상세";
      detailButton.dataset.findingId = item.id;
      appendCell(row, detailButton);
      body.appendChild(row);
    });
    byId("emptyState").classList.toggle("hidden", items.length !== 0);
  }

  function updateSortIndicators() {
    document.querySelectorAll(".sort-button").forEach(function (button) {
      var mark = button.querySelector("span");
      mark.textContent = button.dataset.sort === sortState.key ? (sortState.direction === "asc" ? "▲" : "▼") : "";
    });
  }

  function renderDashboardFilter() {
    document.querySelectorAll("[data-dashboard-filter]").forEach(function (button) {
      button.classList.toggle("active", button.dataset.dashboardFilter === dashboardFilter);
    });
  }

  function render() {
    var filtered = filteredFindings().sort(compareFindings);
    renderDashboardFilter();
    renderSummary(filtered);
    renderInsights(filtered);
    renderRecommendations();
    renderTable(filtered);
    updateSortIndicators();
  }

  function metaItem(label, value, wide) {
    var item = document.createElement("div");
    item.className = "meta-item" + (wide ? " wide" : "");
    var key = document.createElement("span");
    key.className = "meta-label";
    key.textContent = label;
    var val = document.createElement("span");
    val.className = "meta-value";
    val.textContent = value || "-";
    item.appendChild(key);
    item.appendChild(val);
    return item;
  }

  function formatCheckerGuide(guide) {
    if (!guide) return "PDF에서 추출된 체커 공통 가이드가 없습니다.";
    var parts = [];
    if (guide.name) parts.push(guide.code + " - " + guide.name);
    if (guide.plainDescription) parts.push("쉽게 말하면:\n" + guide.plainDescription);
    if (guide.description) parts.push(guide.description);
    if (Array.isArray(guide.cwe) && guide.cwe.length) parts.push("관련 분류: " + guide.cwe.join(", "));
    if (guide.reportGuidance) parts.push("보고서 해결 가이드:\n" + guide.reportGuidance);
    if (guide.reviewNotes) parts.push("검토 관점:\n" + guide.reviewNotes);
    if (Array.isArray(guide.verificationFocus) && guide.verificationFocus.length) parts.push("검증 관점:\n- " + guide.verificationFocus.join("\n- "));
    return parts.join("\n\n") || "체커 공통 가이드가 비어 있습니다.";
  }

  function formatItemGuide(guide) {
    if (!guide) return "저장된 항목별 가이드가 없습니다.";
    var parts = [];
    if (guide.title) parts.push(guide.title);
    if (guide.summary) parts.push(guide.summary);
    if (guide.applicability) parts.push("공통 가이드 적용 판단:\n" + guide.applicability);
    if (Array.isArray(guide.steps) && guide.steps.length) parts.push("검토 및 조치 포인트:\n- " + guide.steps.join("\n- "));
    if (Array.isArray(guide.checkpoints) && guide.checkpoints.length) parts.push("확인 포인트:\n- " + guide.checkpoints.join("\n- "));
    if (Array.isArray(guide.impact) && guide.impact.length) parts.push("영향 범위:\n- " + guide.impact.join("\n- "));
    if (Array.isArray(guide.testPlan) && guide.testPlan.length) parts.push("검증 계획:\n- " + guide.testPlan.join("\n- "));
    if (guide.stableKey) parts.push("고정 키: " + guide.stableKey);
    if (guide.groupGuideRef) parts.push("그룹 대표 가이드: " + guide.groupGuideRef + " 항목을 함께 참조하세요.");
    if (Array.isArray(guide.delta) && guide.delta.length) parts.push("대표와의 차이점:\n- " + guide.delta.join("\n- "));
    if (guide.duplicateGroup) parts.push("중복 그룹: " + guide.duplicateGroup);
    if (Array.isArray(guide.policyQuestions) && guide.policyQuestions.length) parts.push("정책 확인:\n- " + guide.policyQuestions.join("\n- "));
    return parts.join("\n\n") || "항목별 가이드가 비어 있습니다.";
  }

  function formatResult(result) {
    if (!result) return "저장된 처리 결과가 없습니다.";
    var parts = [];
    parts.push("조치 결론: " + (CONCLUSION[result.conclusion] || result.conclusion || "미판정"));
    if (result.reason) parts.push("판단 이유:\n" + result.reason);
    if (Array.isArray(result.resultFiles) && result.resultFiles.length) parts.push("실제 변경 파일/위치:\n- " + result.resultFiles.join("\n- "));
    if (result.resultSummary) parts.push("적용 내용:\n" + result.resultSummary);
    if (result.resultCodeDiff) parts.push("기존/수정 코드 비교:\n" + result.resultCodeDiff);
    if (result.resultGuideComparison) parts.push("공통 가이드 부합 여부:\n" + result.resultGuideComparison);
    if (Array.isArray(result.impact) && result.impact.length) parts.push("영향 범위:\n- " + result.impact.join("\n- "));
    if (result.verification) {
      var verificationParts = ["상태: " + (result.verification.status || "not-run")];
      if (Array.isArray(result.verification.commands) && result.verification.commands.length) verificationParts.push("명령:\n- " + result.verification.commands.join("\n- "));
      if (Array.isArray(result.verification.results) && result.verification.results.length) verificationParts.push("결과:\n- " + result.verification.results.join("\n- "));
      if (Array.isArray(result.verification.limitations) && result.verification.limitations.length) verificationParts.push("제한:\n- " + result.verification.limitations.join("\n- "));
      parts.push("검증:\n" + verificationParts.join("\n"));
    }
    if (Array.isArray(result.duplicates) && result.duplicates.length) parts.push("중복 처리 항목: " + result.duplicates.join(", "));
    if (result.evidenceNote) parts.push("체크리스트 비고 문구:\n" + result.evidenceNote);
    return parts.join("\n\n");
  }

  function renderCurrentDetail() {
    var item = findingById(currentFindingId);
    if (!item) return;
    var itemState = stateFor(item.id);
    var mapping = sourceMapping(item);
    var location = reportedLocation(item);
    var report = item.report || {};
    var guide = checkerGuides[checker(item).code] || null;

    setText("detailKicker", "#" + item.sequence + " · " + item.id);
    setText("detailTitle", checker(item).code + (checker(item).name ? " - " + checker(item).name : ""));
    var meta = byId("detailMeta");
    meta.textContent = "";
    meta.appendChild(metaItem("위험도", risk(item).label));
    meta.appendChild(metaItem("영향도", impact(item).label));
    meta.appendChild(metaItem("언어", item.language));
    meta.appendChild(metaItem("보고 라인", location.reportedLine == null ? "-" : String(location.reportedLine)));
    meta.appendChild(metaItem("현재 라인", mapping.currentLine == null ? "-" : String(mapping.currentLine)));
    meta.appendChild(metaItem("함수", mapping.currentFunction || location.reportedFunction));
    meta.appendChild(metaItem("보고 파일", location.reportedFile, true));
    meta.appendChild(metaItem("현재 파일", mapping.currentFile || location.reportedFile, true));

    byId("detailWorkflow").value = itemState.workflowStatus;
    byId("detailConclusion").value = itemState.conclusion;
    byId("detailNote").value = itemState.note;
    setText("detectedCode", report.detectedCode || "검출 코드가 없습니다.");
    setText("sourceMapping", [
      "매핑 상태: " + (MAPPING[mapping.status] || MAPPING.unreviewed),
      mapping.evidence ? "근거: " + mapping.evidence : "",
      mapping.fingerprint ? "코드 지문: " + mapping.fingerprint : ""
    ].filter(Boolean).join("\n"));
    setText("checkerGuide", formatCheckerGuide(guide));

    var itemGuide = itemGuideCache[item.id] || window.SAST_ITEM_GUIDES[item.id] || null;
    var guidePanel = byId("itemGuide");
    guidePanel.textContent = formatItemGuide(itemGuide);
    guidePanel.classList.toggle("empty-panel", !itemGuide);

    var result = resultCache[item.id] || window.SAST_ITEM_RESULTS[item.id] || null;
    var resultPanel = byId("resultView");
    resultPanel.textContent = formatResult(result);
    resultPanel.classList.toggle("empty-panel", !result);
  }

  function openDetail(id) {
    var item = findingById(id);
    if (!item) return;
    currentFindingId = asString(id);
    renderCurrentDetail();
    byId("taskPrompt").classList.add("hidden");
    byId("taskPrompt").value = "";
    setMessage(
      "taskMessage",
      gateReady() ? "" : "입력 검증 게이트가 READY인 경우에만 처리 요청을 시작할 수 있습니다.",
      gateReady() ? "" : "warning"
    );
    setMessage("answerMessage", "", "");
    byId("answerInput").value = "";
    byId("detailDrawer").classList.add("open");
    byId("detailDrawer").setAttribute("aria-hidden", "false");
    byId("overlay").classList.add("open");
    loadItemGuide(id, false);
    loadItemResult(id, false);
  }

  function closeDetail() {
    byId("detailDrawer").classList.remove("open");
    byId("detailDrawer").setAttribute("aria-hidden", "true");
    byId("overlay").classList.remove("open");
    currentFindingId = null;
  }

  function loadScript(path) {
    return new Promise(function (resolve) {
      var script = document.createElement("script");
      script.src = path + (path.indexOf("?") >= 0 ? "&" : "?") + "ts=" + Date.now();
      script.onload = function () { script.remove(); resolve(true); };
      script.onerror = function () { script.remove(); resolve(false); };
      document.head.appendChild(script);
    });
  }

  async function loadItemGuide(id, force) {
    var key = asString(id);
    if (!force && (itemGuideCache[key] || window.SAST_ITEM_GUIDES[key])) {
      itemGuideCache[key] = itemGuideCache[key] || window.SAST_ITEM_GUIDES[key];
      if (currentFindingId === key) renderCurrentDetail();
      return itemGuideCache[key];
    }
    await loadScript("security-guides/" + encodeURIComponent(key) + ".js");
    var guide = window.SAST_ITEM_GUIDES[key] || null;
    if (guide) itemGuideCache[key] = guide;
    if (currentFindingId === key) renderCurrentDetail();
    return guide;
  }

  function statePatchFromResult(result) {
    if (!result || typeof result !== "object") return {};
    return {
      workflowStatus: validKey(WORKFLOW, result.workflowStatus, "analyzed"),
      conclusion: validKey(CONCLUSION, result.conclusion, "unreviewed"),
      note: asString(result.evidenceNote || result.reason || ""),
      updatedAt: result.updatedAt || nowIso()
    };
  }

  function applyResult(result, preserveVerified) {
    if (!result || !result.id || !findingById(result.id)) return false;
    var key = asString(result.id);
    resultCache[key] = result;
    var current = stateFor(key);
    var incoming = normalizeStateItem(statePatchFromResult(result));
    var curT = timestampOf(current);
    var incT = timestampOf(incoming);
    if (curT !== null && incT !== null && curT > incT) {
      // 브라우저 쪽 상태가 결과 파일보다 최신이면 유지
      return false;
    }
    if (preserveVerified && current.workflowStatus === "verified" && incoming.workflowStatus !== "verified"
      && !(curT !== null && incT !== null && incT > curT)) {
      incoming.workflowStatus = "verified";
    }
    state[key] = Object.assign({}, current, incoming);
    return true;
  }

  // 부팅 시 항목별 결과(index.js)를 상태에 즉시 반영한다.
  // security-results가 상태의 기준이므로 버튼을 누르기 전에도
  // 조치 결과가 바로 보여야 한다.
  function applyBootResults() {
    var applied = 0;
    Object.keys(window.SAST_ITEM_RESULTS || {}).forEach(function (id) {
      if (applyResult(window.SAST_ITEM_RESULTS[id], true)) applied += 1;
    });
    if (applied > 0) saveState();
    return applied;
  }

  async function loadItemResult(id, force) {
    var key = asString(id);
    if (!force && (resultCache[key] || window.SAST_ITEM_RESULTS[key])) {
      var cached = resultCache[key] || window.SAST_ITEM_RESULTS[key];
      applyResult(cached, true);
      saveState();
      render();
      if (currentFindingId === key) renderCurrentDetail();
      return cached;
    }
    await loadScript("security-results/" + encodeURIComponent(key) + ".js");
    var result = window.SAST_ITEM_RESULTS[key] || null;
    if (result) {
      applyResult(result, true);
      saveState();
      render();
    }
    if (currentFindingId === key) renderCurrentDetail();
    return result;
  }

  async function refreshAllResults() {
    var loaded = await loadScript("security-results/index.js");
    var count = 0;
    if (loaded) {
      Object.keys(window.SAST_ITEM_RESULTS || {}).forEach(function (id) {
        if (applyResult(window.SAST_ITEM_RESULTS[id], true)) count += 1;
      });
      resultCache = Object.assign({}, resultCache, window.SAST_ITEM_RESULTS || {});
      saveState();
      render();
      if (currentFindingId) renderCurrentDetail();
    }
    showToast(loaded ? count + "개 처리 결과를 갱신했습니다." : "처리 결과 인덱스를 읽지 못했습니다.", loaded ? "success" : "warning");
  }

  function buildTaskPrompt(item) {
    var itemState = stateFor(item.id);
    var mapping = sourceMapping(item);
    var location = reportedLocation(item);
    var report = item.report || {};
    var guide = checkerGuides[checker(item).code] || {};
    var itemGuide = itemGuideCache[item.id] || window.SAST_ITEM_GUIDES[item.id] || null;
    var reportMeta = profile.report || {};
    return [
      "[SAST 취약점 처리 요청]",
      "프로젝트: " + (profile.projectName || "현재 프로젝트"),
      "리포트: " + (reportMeta.id || "최신 리포트"),
      "순번: " + item.sequence,
      "ID: " + item.id,
      "위험도: " + risk(item).label,
      "영향도: " + impact(item).label,
      "체커: " + checker(item).code + " - " + checker(item).name,
      "보고 파일: " + location.reportedFile,
      "보고 라인: " + (location.reportedLine == null ? "-" : location.reportedLine),
      "보고 함수: " + (location.reportedFunction || "-"),
      "현재 소스 매핑: " + (MAPPING[mapping.status] || MAPPING.unreviewed),
      "현재 파일: " + (mapping.currentFile || location.reportedFile || "-"),
      "현재 라인: " + (mapping.currentLine == null ? "-" : mapping.currentLine),
      "현재 함수: " + (mapping.currentFunction || location.reportedFunction || "-"),
      "현재 작업 단계: " + WORKFLOW[itemState.workflowStatus],
      "현재 조치 결론: " + CONCLUSION[itemState.conclusion],
      "",
      "요청:",
      "1. 현재 소스와 호출부를 확인하고 리포트 검출 코드가 실제로 존재하는지 다시 대조합니다.",
      "2. PDF 체커 가이드는 공통 참고자료이므로 실제 타입과 코드 흐름에 맞는지 검토합니다.",
      "3. 수정, 오탐, 운영 설정, 예외처리, 추가 검토 중 하나로 결론을 남깁니다.",
      "4. 수정한다면 운영 동작을 유지하는 최소 변경을 적용하고 가능한 검증을 실행합니다.",
      "5. 같은 원인으로 함께 처리할 수 있는 항목과 충돌 파일을 확인합니다.",
      "6. 프로젝트 정책으로 확정되지 않은 중요한 결정은 임의로 정하지 말고 질문 하나를 남깁니다.",
      "7. security-results/" + item.id + ".json과 data/progress.json을 갱신합니다.",
      "",
      "응답 형식:",
      "조치 결론:",
      "판단 이유:",
      "실제 변경 파일/위치:",
      "적용 내용:",
      "기존/수정 코드 비교:",
      "공통 가이드 부합 여부:",
      "영향 범위:",
      "검증:",
      "중복 처리 항목:",
      "체크리스트 비고 문구:",
      "",
      "리포트 검출 코드:",
      report.detectedCode || "-",
      "",
      "체커 공통 가이드:",
      formatCheckerGuide(guide),
      "",
      "항목별 검토 가이드:",
      formatItemGuide(itemGuide),
      "",
      "현재 비고:",
      itemState.note || "-"
    ].join("\n");
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (error) {
      var textarea = document.createElement("textarea");
      textarea.value = text;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      var copied = false;
      try { copied = document.execCommand("copy"); } catch (copyError) { copied = false; }
      textarea.remove();
      return copied;
    }
  }

  function setMessage(id, text, kind) {
    var element = byId(id);
    element.textContent = text;
    element.classList.remove("success", "warning");
    if (kind) element.classList.add(kind);
  }

  function cleanSection(text) {
    return asString(text).replace(/```[a-zA-Z0-9_-]*/g, "").replace(/```/g, "").replace(/^\s*[-*]\s?/gm, "").trim();
  }

  function extractSection(text, label) {
    var labels = [
      "조치 결론", "판단 이유", "실제 변경 파일/위치", "적용 내용",
      "기존/수정 코드 비교", "공통 가이드 부합 여부", "영향 범위", "검증",
      "중복 처리 항목", "체크리스트 비고 문구"
    ];
    var escaped = labels.map(function (value) { return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }).join("|");
    var target = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    var expression = new RegExp("(?:^|\\n)\\s*[-*]?\\s*" + target + "\\s*:\\s*\\n?([\\s\\S]*?)(?=\\n\\s*[-*]?\\s*(?:" + escaped + ")\\s*:|$)", "i");
    var match = asString(text).replace(/\r\n/g, "\n").match(expression);
    return match ? cleanSection(match[1]) : "";
  }

  function conclusionFromText(text) {
    var value = asString(text);
    if (value.indexOf("오탐") >= 0) return "false-positive";
    if (value.indexOf("운영") >= 0) return "operations";
    if (value.indexOf("예외") >= 0) return "exception";
    if (value.indexOf("추가 검토") >= 0 || value.indexOf("보류") >= 0) return "needs-review";
    if (value.indexOf("수정") >= 0) return "fix";
    return "unreviewed";
  }

  function splitLines(text) {
    return asString(text).split("\n").map(function (line) { return line.trim(); }).filter(Boolean);
  }

  function parseAnswer() {
    if (!currentFindingId) return;
    if (!gateReady()) {
      setMessage("answerMessage", "입력 검증 게이트가 READY가 아닙니다.", "warning");
      return;
    }
    var raw = byId("answerInput").value;
    if (!raw.trim()) {
      setMessage("answerMessage", "붙여넣은 답변이 없습니다.", "warning");
      return;
    }
    var item = findingById(currentFindingId);
    var conclusionText = extractSection(raw, "조치 결론");
    var verificationText = extractSection(raw, "검증");
    var result = {
      schemaVersion: "1.0",
      id: item.id,
      sequence: item.sequence,
      workflowStatus: conclusionFromText(conclusionText) === "fix" ? "change-complete" : "analyzed",
      conclusion: conclusionFromText(conclusionText),
      reason: extractSection(raw, "판단 이유") || conclusionText,
      resultFiles: splitLines(extractSection(raw, "실제 변경 파일/위치")),
      resultSummary: extractSection(raw, "적용 내용"),
      resultCodeDiff: extractSection(raw, "기존/수정 코드 비교"),
      resultGuideComparison: extractSection(raw, "공통 가이드 부합 여부"),
      impact: splitLines(extractSection(raw, "영향 범위")),
      verification: {
        status: "not-run",
        commands: [],
        results: verificationText ? [verificationText] : [],
        limitations: [],
        verifiedAt: null
      },
      duplicates: splitLines(extractSection(raw, "중복 처리 항목")),
      evidenceNote: extractSection(raw, "체크리스트 비고 문구"),
      updatedAt: nowIso()
    };
    resultCache[item.id] = result;
    window.SAST_ITEM_RESULTS[item.id] = result;
    applyResult(result, true);
    saveState();
    render();
    renderCurrentDetail();
    setMessage("answerMessage", "답변에서 처리 결과를 추출했습니다. 결과 JSON으로 저장할 수 있습니다.", "success");
  }

  function downloadJson(filename, value) {
    var blob = new Blob([JSON.stringify(value, null, 2)], { type: "application/json" });
    var link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(link.href);
  }

  function exportProgress() {
    var allItems = {};
    findings.forEach(function (item) { allItems[item.id] = stateFor(item.id); });
    downloadJson("sast-progress-" + safeFilePart(workspaceId) + ".json", {
      schemaVersion: "1.0",
      workspaceId: workspaceId,
      updatedAt: nowIso(),
      items: allItems
    });
  }

  function extractImportedItems(data) {
    if (!data) return {};
    if (data.items && typeof data.items === "object" && !Array.isArray(data.items)) return data.items;
    if (Array.isArray(data)) {
      return data.reduce(function (items, value) {
        if (value && value.id) items[value.id] = value;
        return items;
      }, {});
    }
    if (typeof data === "object") return data;
    return {};
  }

  function importProgressData(data) {
    var incomingItems = extractImportedItems(data);
    var known = {};
    findings.forEach(function (item) { known[item.id] = true; });
    var filtered = {};
    Object.keys(incomingItems).forEach(function (id) {
      if (known[id]) filtered[id] = incomingItems[id];
    });
    state = mergeStateItems(state, filtered, true).items;
    saveState();
    render();
    if (currentFindingId) renderCurrentDetail();
    return Object.keys(filtered).length;
  }

  function exportCurrentResult() {
    if (!currentFindingId) return;
    var item = findingById(currentFindingId);
    var result = resultCache[currentFindingId] || window.SAST_ITEM_RESULTS[currentFindingId];
    if (!result) {
      var itemState = stateFor(currentFindingId);
      result = {
        schemaVersion: "1.0",
        id: item.id,
        sequence: item.sequence,
        workflowStatus: itemState.workflowStatus,
        conclusion: itemState.conclusion,
        reason: itemState.note,
        resultFiles: [],
        resultSummary: "",
        resultCodeDiff: "",
        resultGuideComparison: "",
        impact: [],
        verification: { status: "not-run", commands: [], results: [], limitations: [], verifiedAt: null },
        duplicates: [],
        evidenceNote: itemState.note,
        updatedAt: nowIso()
      };
    }
    downloadJson(currentFindingId + ".json", result);
  }

  function clearFilters() {
    byId("search").value = "";
    byId("checkerFilter").value = "";
    byId("riskFilter").value = "";
    byId("workflowFilter").value = "";
    byId("conclusionFilter").value = "";
    byId("mappingFilter").value = "";
    byId("languageFilter").value = "";
  }

  function bindEvents() {
    var searchTimer = null;
    ["search", "checkerFilter", "riskFilter", "workflowFilter", "conclusionFilter", "mappingFilter", "languageFilter", "recommendationLimit"].forEach(function (id) {
      byId(id).addEventListener("input", function () {
        if (id !== "recommendationLimit") { dashboardFilter = "all"; pageIndex = 0; }
        if (id === "search") {
          if (searchTimer) clearTimeout(searchTimer);
          searchTimer = setTimeout(render, 150);
          return;
        }
        render();
      });
    });

    byId("resetFilters").addEventListener("click", function () {
      clearFilters();
      dashboardFilter = "all";
      pageIndex = 0;
      render();
    });

    byId("pageSize").addEventListener("input", function () { pageIndex = 0; render(); });
    byId("prevPage").addEventListener("click", function () { pageIndex -= 1; render(); });
    byId("nextPage").addEventListener("click", function () { pageIndex += 1; render(); });

    document.querySelectorAll("[data-dashboard-filter]").forEach(function (button) {
      button.addEventListener("click", function () {
        clearFilters();
        dashboardFilter = button.dataset.dashboardFilter || "all";
        pageIndex = 0;
        render();
      });
    });

    document.querySelectorAll(".sort-button").forEach(function (button) {
      button.addEventListener("click", function () {
        var key = button.dataset.sort;
        if (sortState.key === key) sortState.direction = sortState.direction === "asc" ? "desc" : "asc";
        else sortState = { key: key, direction: "asc" };
        render();
      });
    });

    ["riskStats", "conclusionStats", "mappingStats"].forEach(function (id) {
      byId(id).addEventListener("click", function (event) {
        var button = event.target.closest("button[data-filter-type]");
        if (!button) return;
        dashboardFilter = "all";
        if (button.dataset.filterType === "risk") byId("riskFilter").value = button.dataset.filterValue;
        if (button.dataset.filterType === "conclusion") byId("conclusionFilter").value = button.dataset.filterValue;
        if (button.dataset.filterType === "mapping") byId("mappingFilter").value = button.dataset.filterValue;
        render();
      });
    });

    ["findingsBody", "recommendations"].forEach(function (id) {
      byId(id).addEventListener("click", function (event) {
        var target = event.target.closest("[data-finding-id]");
        if (target) openDetail(target.dataset.findingId);
      });
    });

    byId("closeDrawer").addEventListener("click", closeDetail);
    byId("overlay").addEventListener("click", closeDetail);
    document.addEventListener("keydown", function (event) { if (event.key === "Escape") closeDetail(); });

    byId("detailWorkflow").addEventListener("change", function () {
      if (currentFindingId && gateReady()) updateState(currentFindingId, { workflowStatus: byId("detailWorkflow").value });
    });
    byId("detailConclusion").addEventListener("change", function () {
      if (currentFindingId && gateReady()) updateState(currentFindingId, { conclusion: byId("detailConclusion").value });
    });
    byId("detailNote").addEventListener("input", function () {
      if (currentFindingId && gateReady()) {
        state[currentFindingId] = Object.assign({}, stateFor(currentFindingId), { note: byId("detailNote").value, updatedAt: nowIso() });
        saveState();
      }
    });

    byId("copyTaskPrompt").addEventListener("click", async function () {
      if (!gateReady()) {
        setMessage("taskMessage", "입력 검증 게이트가 READY가 아닙니다.", "warning");
        return;
      }
      var item = findingById(currentFindingId);
      if (!item) return;
      updateState(item.id, { workflowStatus: "in-progress" });
      var prompt = buildTaskPrompt(item);
      byId("taskPrompt").value = prompt;
      byId("taskPrompt").classList.remove("hidden");
      var copied = await copyText(prompt);
      setMessage("taskMessage", copied ? "요청문을 복사했습니다." : "자동 복사가 막혔습니다. 요청문을 직접 선택해 복사하세요.", copied ? "success" : "warning");
      renderCurrentDetail();
    });

    byId("refreshGuide").addEventListener("click", async function () {
      if (!currentFindingId) return;
      var guide = await loadItemGuide(currentFindingId, true);
      showToast(guide ? "항목별 가이드를 갱신했습니다." : "항목별 가이드 파일을 찾지 못했습니다.", guide ? "success" : "warning");
    });
    byId("refreshResult").addEventListener("click", async function () {
      if (!currentFindingId) return;
      var result = await loadItemResult(currentFindingId, true);
      showToast(result ? "처리 결과를 갱신했습니다." : "처리 결과 파일을 찾지 못했습니다.", result ? "success" : "warning");
    });
    byId("refreshResults").addEventListener("click", refreshAllResults);
    byId("parseAnswer").addEventListener("click", parseAnswer);
    byId("exportResult").addEventListener("click", exportCurrentResult);
    byId("exportProgress").addEventListener("click", exportProgress);
    byId("importProgress").addEventListener("click", function () { byId("progressFile").click(); });
    byId("progressFile").addEventListener("change", function (event) {
      var file = event.target.files && event.target.files[0];
      if (!file) return;
      var reader = new FileReader();
      reader.onload = function () {
        try {
          var count = importProgressData(JSON.parse(asString(reader.result)));
          showToast(count + "개 항목의 진행상태를 불러왔습니다.", "success");
        } catch (error) {
          showToast("진행상태 JSON을 읽지 못했습니다.", "warning");
        }
        event.target.value = "";
      };
      reader.readAsText(file, "utf-8");
    });
  }

  initializeHeader();
  applyBootResults();
  renderSyncNotice();
  initializeFilters();
  initializeReadiness();
  bindEvents();
  render();
})();
