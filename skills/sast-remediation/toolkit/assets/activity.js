(function () {
  "use strict";

  var FIELDS = ["schemaVersion", "eventId", "recordedAt", "workspaceId", "reportId", "operationId", "attemptId", "kind", "action", "outcome", "source", "actor", "itemIds", "summary", "before", "after", "evidence", "important"];
  var KINDS = ["started", "finished", "changed", "observation"];
  var OUTCOMES = ["running", "succeeded", "failed", "blocked", "stopped", "info"];
  var SOURCES = ["toolkit", "agent", "browser", "external"];
  var SECRET_NAMES = "password|passwd|pwd|token|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|authorization";
  var SECRET_KEY = new RegExp("^(?:" + SECRET_NAMES + ")$", "i");
  var SECRET_ASSIGNMENT = new RegExp("\\b(" + SECRET_NAMES + ")\\b(\\s*[:=]\\s*)(?:\"[^\"]*\"|'[^']*'|[^\\s,;]+)", "gi");
  var LABELS = { started: "작업 시작", finished: "작업 종료", changed: "변경", observation: "관측",
    running: "시작 기록", succeeded: "작업 성공", failed: "실패", blocked: "차단", stopped: "중단", info: "정보",
    toolkit: "툴킷", agent: "에이전트", browser: "브라우저", external: "외부 변경" };
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
    if (value === null || typeof value === "boolean" || typeof value === "string") return;
    if (typeof value === "number" && Number.isFinite(value)) return;
    if (Array.isArray(value)) { value.forEach(function (v) { jsonValue(v, depth + 1); }); return; }
    if (!object(value)) throw new Error("작업 이력의 상세 값은 JSON이어야 합니다.");
    Object.keys(value).forEach(function (key) {
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
    var seen = Object.create(null), result = [];
    base.concat(incoming).forEach(function (event) {
      validate(event, options);
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
      keys.slice(0, 50).forEach(function (key) { result[key.slice(0, 2000)] = compact(value[key], depth + 1); });
      if (keys.length > 50) result._truncated = keys.length - 50;
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
    select: select, render: render, timestamp: timestamp, formatTimestamp: formatTimestamp,
    equal: function (a, b) { return stable(a) === stable(b); } };
})();
