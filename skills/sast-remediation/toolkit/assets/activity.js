(function () {
  "use strict";

  var FIELDS = ["schemaVersion", "eventId", "recordedAt", "workspaceId", "reportId", "operationId", "attemptId", "kind", "action", "outcome", "source", "actor", "itemIds", "summary", "before", "after", "evidence", "important"];
  var KINDS = ["started", "finished", "changed", "observation"];
  var OUTCOMES = ["running", "succeeded", "failed", "blocked", "stopped", "info"];
  var SOURCES = ["toolkit", "agent", "browser", "external"];
  var RESERVED_KEYS = ["__proto__", "prototype", "constructor"];
  var SECRET_NAMES = "password|passwd|pwd|token|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|authorization";
  var SECRET_KEY = new RegExp("^(?:" + SECRET_NAMES + ")$", "i");
  var SECRET_ASSIGNMENT = new RegExp("\\b(" + SECRET_NAMES + ")\\b(\\s*[:=]\\s*)(?:\"[^\"]*\"|'[^']*'|[^\\s,;]+)", "gi");
  var LABELS = { started: "작업 시작", finished: "작업 종료", changed: "변경", observation: "관측",
    running: "시작 기록", succeeded: "작업 성공", failed: "실패", blocked: "차단", stopped: "중단", info: "정보",
    toolkit: "툴킷", agent: "에이전트", browser: "브라우저", external: "외부 변경" };
  var WORKFLOW_LABELS = { todo: "미착수", "in-progress": "진행 중", analyzed: "분석 완료",
    "change-complete": "변경 완료", verified: "검증 완료", deferred: "보류" };
  var CONCLUSION_LABELS = { unreviewed: "미판정", fix: "수정", "false-positive": "오탐",
    operations: "운영 설정", exception: "예외 처리", "needs-review": "추가 검토" };
  var VERIFICATION_LABELS = { "not-run": "미실행", passed: "통과", failed: "실패",
    partial: "일부 완료", "manual-required": "수동 확인 필요" };
  var RISK_LABELS = { critical: "매우 위험", "very-high": "위험", high: "높음", medium: "보통", low: "낮음" };
  var AUDIENCE_OUTCOME_LABELS = { running: "시작 기록", succeeded: "시도 성공(검증 완료 상태와 별도)",
    failed: "실패", blocked: "차단", stopped: "중단", info: "정보" };
  var FIELD_LABELS = { workflowStatus: "작업 단계", conclusion: "조치 결론", note: "비고",
    reason: "판단 이유", summary: "결과 요약", resultSummary: "적용 내용", resultGuideComparison: "가이드 대조",
    evidenceNote: "근거 메모", nextAction: "다음 확인", minRisk: "최소 위험도",
    policyQuestions: "정책 질문", limitations: "검증 한계", status: "검증 상태" };
  var serial = 0;

  function object(value) { return !!value && typeof value === "object" && !Array.isArray(value); }
  function text(value) { return typeof value === "string" && value.trim().length > 0; }
  function timestamp(value) {
    if (typeof value !== "string") return false;
    var match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))$/.exec(value);
    if (!match || !Number.isFinite(Date.parse(value))) return false;
    var year = Number(match[1]), month = Number(match[2]), day = Number(match[3]);
    var leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    var days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    return year >= 1 && month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1]
      && Number(match[4]) < 24 && Number(match[5]) < 60 && Number(match[6]) < 60
      && (!match[7] || (Number(match[7]) < 24 && Number(match[8]) < 60));
  }
  function formatTimestamp(value) {
    if (!timestamp(value)) return "미확인";
    return new Date(value).toISOString().slice(0, 19).replace("T", " ") + " UTC";
  }
  function jsonValue(value, depth) {
    if (depth > 8) throw new Error("작업 이력의 상세 값이 너무 깊습니다.");
    if (value === null || typeof value === "boolean" || typeof value === "string") return;
    if (typeof value === "number" && Number.isFinite(value)) return;
    if (Array.isArray(value)) { value.forEach(function (v) { jsonValue(v, depth + 1); }); return; }
    if (!object(value)) throw new Error("작업 이력의 상세 값은 JSON이어야 합니다.");
    Object.keys(value).forEach(function (key) {
      if (RESERVED_KEYS.indexOf(key) !== -1) throw new Error("작업 이력에 허용되지 않는 예약 키가 있습니다.");
      jsonValue(value[key], depth + 1);
    });
  }
  function byteSize(value) {
    return Array.from(JSON.stringify(value, null, 2) + "\n").reduce(function (size, c) {
      var point = c.codePointAt(0);
      return size + (point < 128 ? 1 : point < 2048 ? 2 : point < 65536 ? 3 : 4);
    }, 0);
  }
  function validate(event, options) {
    var settings = options || {};
    if (!object(event) || Object.keys(event).length !== FIELDS.length
      || !FIELDS.every(function (key) { return Object.prototype.hasOwnProperty.call(event, key); })
      || event.schemaVersion !== "1.0" || !timestamp(event.recordedAt)
      || !["eventId", "operationId", "attemptId"].every(function (key) { return typeof event[key] === "string" && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,199}$/.test(event[key]); })
      || !["action", "actor", "summary"].every(function (key) { return text(event[key]); })
      || !["workspaceId", "reportId"].every(function (key) { return event[key] === null || text(event[key]); })
      || KINDS.indexOf(event.kind) === -1 || OUTCOMES.indexOf(event.outcome) === -1
      || SOURCES.indexOf(event.source) === -1 || typeof event.summary !== "string"
      || !object(event.before) || !object(event.after) || typeof event.important !== "boolean"
      || !["itemIds", "evidence"].every(function (key) { return Array.isArray(event[key]) && event[key].every(text); })) {
      throw new Error("작업 이력의 필수 필드·형식이 올바르지 않습니다.");
    }
    if (Object.prototype.hasOwnProperty.call(settings, "workspaceId") && event.workspaceId !== settings.workspaceId) {
      throw new Error("작업 이력의 작업공간이 현재 백업과 다릅니다.");
    }
    if (settings.browserOnly && event.source !== "browser") throw new Error("브라우저 백업에는 브라우저 출처의 이력만 허용됩니다.");
    if (event.action === "canonical.reconcile" && (["toolkit", "external"].indexOf(event.source) === -1
      || ["changed", "observation"].indexOf(event.kind) === -1)) {
      throw new Error("내부 정본 대조에 예약된 작업 이름은 해당 출처의 관측 기록에만 허용됩니다.");
    }
    jsonValue(event.before, 0); jsonValue(event.after, 0);
    if ((event.kind === "started" && event.outcome !== "running")
      || (event.kind === "finished" && ["succeeded", "failed", "blocked", "stopped"].indexOf(event.outcome) === -1)) {
      throw new Error("작업 이력의 시작·종료와 결과가 맞지 않습니다.");
    }
    if (byteSize(event) > 32768) throw new Error("작업 이력 한 건은 32768바이트를 넘을 수 없습니다.");
    if (["action", "actor", "summary", "before", "after", "evidence"].some(function (key) { return stable(redact(event[key])) !== stable(event[key]); })) {
      throw new Error("작업 이력에 명시적인 비밀 값이 있습니다. 마스킹한 백업으로 다시 확인하세요.");
    }
    return event;
  }
  function stable(value) {
    if (Array.isArray(value)) return "[" + value.map(stable).join(",") + "]";
    if (object(value)) return "{" + Object.keys(value).sort().map(function (key) { return JSON.stringify(key) + ":" + stable(value[key]); }).join(",") + "}";
    return JSON.stringify(value);
  }
  function merge(base, incoming, options) {
    if (!Array.isArray(base) || !Array.isArray(incoming)) throw new Error("작업 이력 목록의 형식이 올바르지 않습니다.");
    var seen = Object.create(null), operations = Object.create(null), result = [];
    base.concat(incoming).forEach(function (event) {
      validate(event, options);
      if (event.action !== "canonical.reconcile") {
        var identity = stable([event.workspaceId, event.reportId, event.action, event.source,
          event.itemIds.filter(function (value, index, values) { return values.indexOf(value) === index; }).slice().sort()]);
        if (Object.prototype.hasOwnProperty.call(operations, event.operationId) && operations[event.operationId] !== identity) {
          throw new Error("같은 작업 ID의 논리 작업 정보가 충돌합니다: " + event.operationId);
        }
        operations[event.operationId] = identity;
      }
      if (Object.prototype.hasOwnProperty.call(seen, event.eventId)) {
        if (stable(seen[event.eventId]) !== stable(event)) throw new Error("작업 이력 ID 충돌: " + event.eventId);
      } else { seen[event.eventId] = event; result.push(event); }
    });
    return result;
  }
  function redact(value) {
    if (typeof value === "string") return value
      .replace(SECRET_ASSIGNMENT, "$1$2[REDACTED]")
      .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]");
    if (Array.isArray(value)) return value.map(redact);
    if (object(value)) {
      var result = Object.create(null);
      Object.keys(value).forEach(function (key) {
        result[key] = SECRET_KEY.test(key) ? "[REDACTED]" : redact(value[key]);
      });
      return result;
    }
    return value;
  }
  function compact(value, depth) {
    if (typeof value === "string") return value.length <= 2000 ? value : value.slice(0, 1987) + "…[truncated]";
    if ((object(value) || Array.isArray(value)) && depth >= 5) return "[TRUNCATED]";
    if (Array.isArray(value)) return value.slice(0, 50).map(function (v) { return compact(v, depth + 1); });
    if (object(value)) {
      var result = Object.create(null), keys = Object.keys(value);
      var omitted = keys.filter(function (key) { return RESERVED_KEYS.indexOf(key) !== -1; });
      var allowed = keys.filter(function (key) { return RESERVED_KEYS.indexOf(key) === -1; });
      allowed.slice(0, 50).forEach(function (key) { result[key.slice(0, 2000)] = compact(value[key], depth + 1); });
      if (omitted.length) result._omittedKeys = omitted;
      if (allowed.length > 50) result._truncated = allowed.length - 50;
      return result;
    }
    return value;
  }
  function id() {
    if (window.crypto && typeof window.crypto.randomUUID === "function") return "browser-" + window.crypto.randomUUID();
    serial += 1;
    return "browser-" + Date.now().toString(36) + "-" + serial.toString(36) + "-" + Math.random().toString(36).slice(2);
  }
  function create(options) {
    var eventId = id();
    var event = { schemaVersion: "1.0", eventId: eventId, recordedAt: new Date().toISOString(),
      workspaceId: options.workspaceId, reportId: options.reportId || null,
      operationId: eventId, attemptId: eventId, kind: "changed", action: options.action,
      outcome: "info", source: "browser", actor: "user", itemIds: options.itemIds || [],
      summary: options.summary || "브라우저 변경", before: options.before || {},
      after: options.after || {}, evidence: [], important: true };
    ["action", "actor", "summary", "before", "after", "evidence"].forEach(function (key) { event[key] = compact(redact(event[key]), 0); });
    if (byteSize(event) > 32768) {
      event.before = { truncated: true, reason: "이력 크기 제한으로 상세 값을 생략했습니다. 상태·결과 백업 원본을 대조하세요." };
      event.after = { truncated: true, reason: "이력 크기 제한으로 상세 값을 생략했습니다. 상태·결과 백업 원본을 대조하세요." };
    }
    return validate(event);
  }
  function attemptKey(event) { return JSON.stringify([event.workspaceId, event.reportId, event.operationId, event.attemptId, event.action, event.source, event.itemIds]); }
  function project(events) {
    var ended = Object.create(null);
    events.forEach(function (event) { if (event.kind === "finished") ended[attemptKey(event)] = true; });
    return { unfinished: events.filter(function (event) { return event.kind === "started" && !ended[attemptKey(event)]; }),
      errors: events.filter(function (event) { return ["failed", "blocked", "stopped"].indexOf(event.outcome) !== -1; }) };
  }
  function select(events, options) {
    var settings = options || {}, projection = project(events), pending = Object.create(null);
    projection.unfinished.forEach(function (event) { pending[event.eventId] = true; });
    var result = events.map(function (event, index) { return { event: event, index: index }; }).filter(function (entry) {
      var event = entry.event;
      if (settings.itemId && event.itemIds.indexOf(settings.itemId) === -1) return false;
      if (settings.reportId !== undefined && event.reportId !== settings.reportId) return false;
      if (settings.source && event.source !== settings.source) return false;
      if (settings.mode === "errors" && ["failed", "blocked", "stopped"].indexOf(event.outcome) === -1) return false;
      if (settings.mode === "important" && !event.important) return false;
      if (settings.mode === "unfinished" && !pending[event.eventId]) return false;
      var date = new Date(event.recordedAt).toISOString().slice(0, 10);
      if (settings.from && date < settings.from) return false;
      if (settings.to && date > settings.to) return false;
      return !settings.search || stable(event).toLowerCase().indexOf(settings.search.toLowerCase()) !== -1;
    }).sort(function (a, b) { return Date.parse(b.event.recordedAt) - Date.parse(a.event.recordedAt) || b.index - a.index; });
    var pages = Math.max(1, Math.ceil(result.length / 50));
    var page = Math.max(1, Math.min(pages, Math.floor(Number(settings.page)) || 1));
    return { events: result.slice((page - 1) * 50, page * 50).map(function (entry) { return entry.event; }),
      total: result.length, page: page, pages: pages, unfinishedIds: pending, projection: projection };
  }
  function operationKey(event) {
    return stable([event.workspaceId, event.reportId, event.operationId, event.action, event.source,
      event.itemIds.filter(function (value, index, values) { return values.indexOf(value) === index; }).slice().sort()]);
  }
  function classify(event) {
    var action = event.action.toLowerCase();
    if (action === "canonical.reconcile") {
      if (event.kind === "observation") return "system";
      if (readableChanges([event]).length) return "work";
      return unknownCanonicalChanges(event) ? "unknown" : "system";
    }
    if (/^(?:browser\.(?:state|note|draft|import)|remediation|verification|review|analysis|triage|toolkit\.scope|state\.(?:seal-verification|recover-progress))$/.test(action)) return "work";
    if (/^(?:(?:toolkit|sast[_-]?(?:toolkit|state|activity))\.)?(?:sync|checkpoint|snapshot|baseline|status|query|validate|preflight|init)$/.test(action)
      || /^(?:state\.(?:checkpoint|snapshot|status)|toolkit\.gate)$/.test(action)) return "system";
    return "unknown";
  }
  function selectAudience(events, options) {
    var settings = options || {}, audience = settings.audience === "system" ? "system" : "work";
    var groups = Object.create(null), rows = [];
    events.forEach(function (event, index) {
      var classification = classify(event);
      var key = operationKey(event), row = groups[key];
      if (!row) {
        row = groups[key] = { records: [], firstIndex: index, action: event.action, source: event.source,
          workspaceId: event.workspaceId, reportId: event.reportId, operationId: event.operationId,
          itemIds: event.itemIds.slice(), classification: classification };
        rows.push(row);
      }
      if (classification === "work" || row.classification === "system" && classification === "unknown") {
        row.classification = classification;
      }
      row.records.push({ event: event, index: index });
    });
    rows.forEach(function (row) {
      row.records.sort(function (a, b) { return Date.parse(a.event.recordedAt) - Date.parse(b.event.recordedAt) || a.index - b.index; });
      row.records = row.records.map(function (entry) { return entry.event; });
      var attempts = Object.create(null);
      row.records.forEach(function (event, recordIndex) {
        var attempt = attempts[event.attemptId] || { started: false, finished: false, terminal: null,
          last: null, firstOrder: recordIndex, startOrder: null };
        if (event.kind === "started") {
          attempt.started = true;
          if (attempt.startOrder === null) attempt.startOrder = recordIndex;
        }
        if (event.kind === "finished") { attempt.finished = true; attempt.terminal = event; }
        attempt.last = event;
        attempts[event.attemptId] = attempt;
      });
      var latest = row.records[row.records.length - 1];
      var attemptValues = Object.keys(attempts).map(function (key) { return attempts[key]; });
      var lifecycleAttempts = attemptValues.filter(function (attempt) { return attempt.started || attempt.finished; });
      var latestAttempt = (lifecycleAttempts.length ? lifecycleAttempts : attemptValues).sort(function (a, b) {
        var aOrder = a.startOrder === null ? a.firstOrder : a.startOrder;
        var bOrder = b.startOrder === null ? b.firstOrder : b.startOrder;
        return bOrder - aOrder;
      })[0];
      row.attemptCount = Object.keys(attempts).length;
      row.unfinishedAttemptCount = Object.keys(attempts).filter(function (key) {
        return attempts[key].started && !attempts[key].finished;
      }).length;
      row.currentUnfinished = !!(latestAttempt && latestAttempt.started && !latestAttempt.finished);
      row.outcome = latestAttempt && latestAttempt.terminal ? latestAttempt.terminal.outcome
        : row.currentUnfinished ? "running" : latest.outcome;
      row.recordedAt = latest.recordedAt;
      row.summary = latest.summary || latest.action;
    });
    rows = rows.filter(function (row) {
      var systemImpact = row.classification === "system" && (row.unfinishedAttemptCount
        || ["failed", "blocked", "stopped"].indexOf(row.outcome) !== -1);
      if (audience === "system" ? row.classification === "work" : row.classification !== "work" && !systemImpact) return false;
      if (settings.itemId && row.itemIds.indexOf(settings.itemId) === -1) return false;
      if (settings.reportId !== undefined && row.reportId !== settings.reportId) return false;
      if (settings.source && row.source !== settings.source) return false;
      if (settings.mode === "errors" && !row.records.some(function (event) {
        return ["failed", "blocked", "stopped"].indexOf(event.outcome) !== -1;
      })) return false;
      if (settings.mode === "important" && !row.records.some(function (event) { return event.important; })) return false;
      if (settings.mode === "unfinished" && !row.unfinishedAttemptCount) return false;
      if ((settings.from || settings.to) && !row.records.some(function (event) {
        var date = new Date(event.recordedAt).toISOString().slice(0, 10);
        return (!settings.from || date >= settings.from) && (!settings.to || date <= settings.to);
      })) return false;
      return !settings.search || row.records.some(function (event) {
        return stable(event).toLowerCase().indexOf(settings.search.toLowerCase()) !== -1;
      });
    });
    var unknownTotal = rows.filter(function (row) { return row.classification === "unknown"; }).length;
    rows.sort(function (a, b) { return Date.parse(b.recordedAt) - Date.parse(a.recordedAt) || b.firstIndex - a.firstIndex; });
    var pages = Math.max(1, Math.ceil(rows.length / 50));
    var page = Math.max(1, Math.min(pages, Math.floor(Number(settings.page)) || 1));
    var projection = project(events), unfinishedIds = Object.create(null);
    projection.unfinished.forEach(function (event) { unfinishedIds[event.eventId] = true; });
    return { rows: rows.slice((page - 1) * 50, page * 50), total: rows.length, page: page, pages: pages,
      unknownTotal: unknownTotal, unfinishedIds: unfinishedIds, projection: projection };
  }
  function displayValue(key, value) {
    if (value === null || value === undefined || value === "") return "미확인";
    if (key === "workflowStatus") return WORKFLOW_LABELS[value] || String(value);
    if (key === "conclusion") return CONCLUSION_LABELS[value] || String(value);
    if (key === "status") return VERIFICATION_LABELS[value] || String(value);
    if (key === "minRisk") return RISK_LABELS[value] || String(value);
    if (Array.isArray(value)) return value.length ? value.map(function (entry) { return typeof entry === "string" ? entry : JSON.stringify(entry); }).join(", ") : "없음";
    if (object(value)) return JSON.stringify(value);
    if (typeof value === "boolean") return value ? "예" : "아니요";
    return String(value);
  }
  function collectKnown(value, found, path, depth) {
    if (!object(value) || depth > 6) return;
    Object.keys(value).forEach(function (key) {
      var nextPath = path ? path + "." + key : key;
      if (Object.prototype.hasOwnProperty.call(FIELD_LABELS, key)
        && (key !== "status" || nextPath.toLowerCase().indexOf("verification") !== -1)) found[nextPath] = { key: key, value: value[key] };
      if (object(value[key])) collectKnown(value[key], found, nextPath, depth + 1);
    });
  }
  function unknownCanonicalFields(value, found, path, depth) {
    var technical = { updatedAt: true, generatedAt: true, recordedAt: true, observedAt: true,
      sha256: true, exists: true, record: true, itemIds: true, content: true, readable: true,
      sourceSnapshot: true, id: true, sequence: true };
    if (depth > 6 || value === null || value === undefined) return;
    if (Array.isArray(value)) {
      value.forEach(function (entry, index) { unknownCanonicalFields(entry, found, path + "." + index, depth + 1); });
      return;
    }
    if (!object(value)) { found[path] = value; return; }
    Object.keys(value).forEach(function (key) {
      var nextPath = path ? path + "." + key : key;
      if (Object.prototype.hasOwnProperty.call(FIELD_LABELS, key) || technical[key]) return;
      unknownCanonicalFields(value[key], found, nextPath, depth + 1);
    });
  }
  function unknownCanonicalChanges(event) {
    var before = Object.create(null), after = Object.create(null);
    unknownCanonicalFields(object(event.before.value) ? event.before.value : {}, before, "", 0);
    unknownCanonicalFields(object(event.after.value) ? event.after.value : {}, after, "", 0);
    return Object.keys(Object.assign({}, before, after)).some(function (path) {
      return stable(before[path]) !== stable(after[path]);
    });
  }
  function appendComparison(lines, beforeValue, afterValue, mode) {
    var before = Object.create(null), after = Object.create(null);
    collectKnown(beforeValue, before, "", 0); collectKnown(afterValue, after, "", 0);
    Object.keys(Object.assign({}, before, after)).forEach(function (path) {
      var previous = before[path], next = after[path], key = (next || previous).key;
      var a = previous ? previous.value : undefined, b = next ? next.value : undefined;
      if (previous && next && stable(a) === stable(b)) return;
      if ((mode === "start" || mode === "lifecycle") && previous && !next) lines.push("시작 시 " + FIELD_LABELS[key] + ": " + displayValue(key, a));
      else if ((mode === "finish" || mode === "lifecycle") && next && !previous) lines.push("종료 시 " + FIELD_LABELS[key] + ": " + displayValue(key, b));
      else if (mode === "observation" && !previous && next) lines.push(FIELD_LABELS[key] + ": " + displayValue(key, b) + " (관측값)");
      else lines.push(FIELD_LABELS[key] + ": " + displayValue(key, a) + " → " + displayValue(key, b));
    });
  }
  function readableChanges(records) {
    var lines = [], attempts = Object.create(null);
    records.forEach(function (event) {
      var beforeValue = event.action === "canonical.reconcile" && object(event.before.value) ? event.before.value : event.before;
      var afterValue = event.action === "canonical.reconcile" && object(event.after.value) ? event.after.value : event.after;
      if (event.kind === "started" || event.kind === "finished") {
        var attempt = attempts[event.attemptId] || { before: null, after: null };
        if (event.kind === "started") {
          attempt.before = beforeValue;
          if (Object.keys(afterValue).length) attempt.after = afterValue;
        }
        if (event.kind === "finished") {
          if (!attempt.before && Object.keys(beforeValue).length) attempt.before = beforeValue;
          attempt.after = afterValue;
        }
        attempts[event.attemptId] = attempt;
      } else appendComparison(lines, beforeValue, afterValue, event.kind === "observation" ? "observation" : "change");
    });
    Object.keys(attempts).forEach(function (key) {
      var attempt = attempts[key];
      if (attempt.before && attempt.after) appendComparison(lines, attempt.before, attempt.after, "lifecycle");
      else if (attempt.before) appendComparison(lines, attempt.before, {}, "start");
      else if (attempt.after) appendComparison(lines, {}, attempt.after, "finish");
    });
    return lines.filter(function (line, index, values) { return values.indexOf(line) === index; });
  }
  function hasTruncated(value, depth) {
    if (depth > 6 || (!object(value) && !Array.isArray(value))) return false;
    if (object(value) && (value.truncated === true || value._truncated !== undefined)) return true;
    return Object.keys(value).some(function (key) { return hasTruncated(value[key], depth + 1); });
  }
  function provenance(row, settings) {
    var fileCount = row.records.filter(function (event) { return settings.fileIds && settings.fileIds[event.eventId]; }).length;
    var storedCount = row.records.filter(function (event) { return settings.persistedIds && settings.persistedIds[event.eventId]; }).length;
    if (fileCount === row.records.length) return "파일 원본";
    if (fileCount) return "파일·브라우저 기록";
    if (storedCount === row.records.length) return "브라우저 저장 · 정본 반영 미확인";
    return "현재 화면 · 브라우저 저장 미확인";
  }
  function rowImpact(row) {
    if (row.currentUnfinished) return "영향: 최신 시도의 종료 기록이 없습니다. 현재 상태와 실제 실행 여부를 대조하세요.";
    if (row.unfinishedAttemptCount) return "확인 필요: 종료 미확인 시도 " + row.unfinishedAttemptCount + "건이 남아 있습니다. 최신 시도 결과와 별도로 현재 상태를 대조하세요.";
    if (row.outcome === "failed") return "영향: 최신 시도가 실패했습니다. 오류와 다음 확인 사항은 진단 상세에서 확인하세요.";
    if (row.outcome === "blocked") return "영향: 필요한 조건이 충족되지 않아 최신 시도를 진행하지 못했습니다.";
    if (row.outcome === "stopped") return "영향: 최신 시도가 중단되어 완료 여부를 다시 확인해야 합니다.";
    return "";
  }
  function friendlyTitle(row, changes) {
    if (row.classification === "unknown") return "분류 미확인 · " + (row.action === "canonical.reconcile" ? "정본 변경 관측" : row.summary);
    if (row.action !== "canonical.reconcile") return row.summary;
    if (changes.some(function (line) { return line.indexOf("최소 위험도:") !== -1; })) return "처리 범위 변경";
    if (changes.some(function (line) { return /^(?:시작 시 |종료 시 )?(?:작업 단계|조치 결론):/.test(line); })) return "작업 상태·결론 변경";
    if (changes.some(function (line) { return /^(?:시작 시 |종료 시 )?(?:비고|다음 확인):/.test(line); })) return "작업 메모·다음 확인 변경";
    if (changes.some(function (line) { return /^(?:시작 시 |종료 시 )?검증/.test(line); })) return "검증 기록 변경";
    if (changes.length) return "처리 결과 변경";
    return row.records.some(function (event) { return event.kind === "observation"; }) ? "기준 상태 관측" : "정본 파일 변경 관측";
  }
  function renderAudience(document, container, rows, options) {
    var settings = options || {};
    container.textContent = "";
    if (!rows.length) {
      container.textContent = settings.emptyMessage || "조건에 맞는 기록이 없습니다. 기록이 없다는 사실만으로 작업이 없었다고 판단할 수는 없습니다.";
      return;
    }
    rows.forEach(function (row) {
      var entry = document.createElement("article"), heading = document.createElement("h3"), meta = document.createElement("p");
      var changes = readableChanges(row.records);
      entry.className = "activity-entry activity-audience-entry";
      heading.className = "activity-event-title";
      heading.textContent = friendlyTitle(row, changes);
      meta.className = "activity-event-meta";
      var hasLifecycle = row.records.some(function (event) { return event.kind === "started" || event.kind === "finished"; });
      meta.textContent = (row.action === "canonical.reconcile" ? "관측 시각 " : "기록 시각 ") + formatTimestamp(row.recordedAt)
        + (hasLifecycle ? " · 현재 결과 " + (AUDIENCE_OUTCOME_LABELS[row.outcome] || row.outcome) + " · 시도 " + row.attemptCount + "회"
          : " · " + (row.records.some(function (event) { return event.kind === "changed"; }) ? "변경 기록" : "관측 기록"))
        + " · 출처 " + (LABELS[row.source] || row.source) + " · " + provenance(row, settings) + " · 차수 " + (row.reportId || "미확인");
      entry.appendChild(heading); entry.appendChild(meta);
      var body = document.createElement("div");
      body.className = "activity-user-detail";
      var target = document.createElement("p");
      target.textContent = "대상: " + (row.itemIds.join(", ") || "전체/미지정");
      body.appendChild(target);
      changes.forEach(function (line) { var p = document.createElement("p"); p.textContent = line; body.appendChild(p); });
      if (row.records.some(function (event) { return hasTruncated(event.before, 0) || hasTruncated(event.after, 0); })) {
        var truncated = document.createElement("p");
        truncated.className = "activity-impact";
        truncated.textContent = "변경 상세가 생략되어 알 수 없는 부분이 있습니다. 진단 상세의 참조와 원본을 대조하세요.";
        body.appendChild(truncated);
      }
      var latest = row.records[row.records.length - 1];
      if (latest.evidence.length) { var evidence = document.createElement("p"); evidence.textContent = "근거 참조: " + latest.evidence.join(", "); body.appendChild(evidence); }
      var impactText = rowImpact(row);
      if (impactText) { var impact = document.createElement("p"); impact.className = "activity-impact"; impact.textContent = impactText; body.appendChild(impact); }
      entry.appendChild(body);
      var diagnostics = document.createElement("details"), diagnosticsSummary = document.createElement("summary");
      diagnostics.className = "activity-diagnostics";
      diagnosticsSummary.textContent = "진단 상세";
      diagnostics.appendChild(diagnosticsSummary);
      var raw = document.createElement("div");
      raw.className = "activity-raw-list";
      render(document, raw, row.records, settings);
      diagnostics.appendChild(raw); entry.appendChild(diagnostics); container.appendChild(entry);
    });
  }
  function render(document, container, events, options) {
    var settings = options || {};
    container.textContent = "";
    if (!events.length) { container.textContent = "조건에 맞는 작업 이력이 없습니다. 과거 이력이 없다는 사실만으로 작업이 없었다고 판단할 수는 없습니다."; return; }
    events.forEach(function (event) {
      var details = document.createElement("details"), summary = document.createElement("summary");
      details.className = "activity-entry";
      var file = settings.fileIds && settings.fileIds[event.eventId];
      var stored = settings.persistedIds && settings.persistedIds[event.eventId];
      var provenance = file ? "파일 기록" : stored ? "브라우저 저장 · 정본 반영 미확인" : "현재 화면 · 브라우저 저장 미확인";
      var heading = document.createElement("span");
      heading.className = "activity-event-title";
      heading.textContent = event.summary || event.action;
      var meta = document.createElement("span");
      meta.className = "activity-event-meta";
      meta.textContent = formatTimestamp(event.recordedAt) + " · " + LABELS[event.kind] + " · " + LABELS[event.outcome]
        + (settings.unfinishedIds && settings.unfinishedIds[event.eventId] ? " · 종료 미확인" : "")
        + " · " + provenance + " · 출처 " + LABELS[event.source] + " · 차수 " + (event.reportId || "미확인");
      summary.appendChild(heading); summary.appendChild(meta); details.appendChild(summary);
      var body = document.createElement("pre");
      body.className = "activity-event-detail";
      body.textContent = "항목: " + (event.itemIds.join(", ") || "전체/미지정") + "\n작업: " + event.action
        + "\n기록 시각(원문): " + event.recordedAt
        + "\n기록 주체: " + (event.actor.trim().toLowerCase() === "unknown" ? "미확인" : event.actor)
        + "\n작업공간: " + (event.workspaceId || "미확인")
        + "\n이벤트: " + event.eventId + "\n작업 ID: " + event.operationId + "\n시도 ID: " + event.attemptId
        + "\n변경 전:\n" + JSON.stringify(event.before, null, 2) + "\n변경 후:\n" + JSON.stringify(event.after, null, 2)
        + "\n근거 참조:\n" + (event.evidence.join("\n") || "없음")
        + (settings.unfinishedIds && settings.unfinishedIds[event.eventId] ? "\n종료 기록이 없습니다. 실행 중인지, 중단됐는지는 현재 작업과 파일을 대조해야 합니다." : "");
      details.appendChild(body); container.appendChild(details);
    });
  }
  window.SAST_ACTIVITY = { validate: validate, merge: merge, create: create, project: project,
    select: select, selectAudience: selectAudience, render: render, renderAudience: renderAudience,
    timestamp: timestamp, formatTimestamp: formatTimestamp,
    equal: function (a, b) { return stable(a) === stable(b); } };
})();
