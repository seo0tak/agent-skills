import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type { ProgressView, TokenTotals, UsageView } from '../types'

// Claude Code 전용 진행률 패널. 프로젝트에 툴킷 복사본이 있거나 이 스킬이 실행되면 열린다.
// 진행률은 툴킷의 query --summary(읽기 전용)를 그대로 보여 줄 뿐 상태를 바꾸지 않는다.
const TOOLKIT = 'sast-remediation-toolkit'
const PANE = 'sast-progress'
const TITLE = 'SAST 진행률 · 토큰'
const REFRESH_GAP_MS = 5000
const SKILL_NAME = /(^|:)sast-remediation$/

const progress = atom({ plugin: 'sast-remediation', key: 'progress' } as const,
  { kind: 'none', reason: '아직 확인하지 않았습니다.' } as ProgressView)
const usage = atom({ plugin: 'sast-remediation', key: 'usage' } as const, { rateLimits: [] } as UsageView)
const tokens = atom({ plugin: 'sast-remediation', key: 'tokens' } as const,
  { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, requests: 0 } as TokenTotals)
// 이 세션에서 패널을 쓰는지: 툴킷이 있거나 스킬이 실행됐을 때만 참. 그 전에는 화면에 아무것도 내지 않는다.
const active = atom({ plugin: 'sast-remediation', key: 'active' } as const, false)

type Summary = {
  total: number
  by: { workflowStatus: Record<string, number> }
  byChecker: Record<string, { total: number; verified: number; deferred: number; remaining: number }>
}

let lastRefresh = 0

export function parseSummary(stdout: string, checkedAt: number): ProgressView {
  const summary = JSON.parse(stdout) as Summary
  const byStatus = summary.by?.workflowStatus ?? {}
  const checkers = Object.entries(summary.byChecker ?? {}).map(([code, c]) => ({
    code, total: c.total, verified: c.verified, remaining: c.remaining,
  }))
  return {
    kind: 'ok',
    total: summary.total,
    verified: byStatus.verified ?? 0,
    deferred: byStatus.deferred ?? 0,
    byStatus,
    checkers,
    checkedAt,
  }
}

async function refreshProgress($: EngineInterface, force = false) {
  const now = await $.clock.now()
  if (!force && now - lastRefresh < REFRESH_GAP_MS) return
  lastRefresh = now
  let view: ProgressView
  if (!(await $.fs.exists(`${TOOLKIT}/tools/sast_toolkit.py`))) {
    view = { kind: 'none', reason: `이 프로젝트에 ${TOOLKIT}/이 아직 없습니다. 스킬이 툴킷을 복사하면 표시됩니다.` }
  } else if (!(await $.fs.exists(`${TOOLKIT}/data/findings.json`))) {
    view = { kind: 'none', reason: '아직 검출이 등록되지 않았습니다(01 초기 분석 전).' }
  } else {
    try {
      const run = await $.process.run(
        ['python3', '-B', 'tools/sast_toolkit.py', 'query', '--summary'],
        { cwd: TOOLKIT, timeoutMs: 20000 })
      view = run.exitCode === 0
        ? parseSummary(run.stdout, now)
        : { kind: 'error', message: (run.stderr || run.stdout).trim().split('\n')[0] || `종료 코드 ${run.exitCode}`, checkedAt: now }
    } catch (error) {
      view = { kind: 'error', message: String(error), checkedAt: now }
    }
  }
  await update($, progress, () => view)
  await showStatus($)
}

async function activate($: EngineInterface) {
  await update($, active, () => true)
  await refreshProgress($, true)
  await $.ui.open({ id: PANE, title: TITLE })
}

function percent(part: number, whole: number) {
  return whole > 0 ? Math.floor((part / whole) * 100) : 0
}

function bar(value: number, width = 20) {
  const filled = Math.round((Math.min(100, Math.max(0, value)) / 100) * width)
  return '█'.repeat(filled) + '░'.repeat(width - filled)
}

function compact(n?: number) {
  if (n === undefined) return '-'
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`
  return String(n)
}

function clockText(ms: number) {
  const d = new Date(ms)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

async function showStatus($: EngineInterface) {
  if (!(await read($, active))) return
  const p = await read($, progress)
  const u = await read($, usage)
  const parts: string[] = []
  parts.push(p.kind === 'ok' ? `SAST ${percent(p.verified, p.total)}% (${p.verified}/${p.total})` : 'SAST 준비 전')
  if (u.contextPercent !== undefined) parts.push(`ctx ${Math.round(u.contextPercent)}%`)
  if (u.costUsd !== undefined) parts.push(`$${u.costUsd.toFixed(2)}`)
  await $.ui.status(parts.join(' · '))
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    const started = await next(e)
    await $.command.register({ name: 'sast-progress', description: 'SAST 진행률과 토큰 사용량 패널을 열고 새로 고친다' })
    const now = await $.session.usage()
    await update($, usage, () => ({
      contextPercent: now.context.percent, contextTokens: now.context.tokens,
      contextWindow: now.context.window, costUsd: now.cost?.usd,
      rateLimits: now.rateLimits.map(r => ({ kind: r.kind, percentUsed: r.percentUsed })),
    }))
    // 툴킷 복사본이 있는 프로젝트에서만 시작부터 연다. 없으면 스킬이 실행될 때까지 조용히 있는다.
    if (await $.fs.exists(`${TOOLKIT}/tools/sast_toolkit.py`)) await activate($)
    return started
  })

  // 이 스킬이 실행되면(슬래시 명령·Skill 도구) 패널을 연다.
  on('skill.prompt', async ($, e, next) => {
    const expanded = await next(e)
    if (SKILL_NAME.test(e.skill)) await activate($)
    return expanded
  })

  on('command.run', { command: 'sast-progress' }, async $ => {
    await activate($)
    return { text: 'SAST 진행률 패널을 열고 새로 고쳤습니다.' }
  })

  on('session.measure', async ($, e, next) => {
    await update($, usage, () => ({
      contextPercent: e.context.percent, contextTokens: e.context.tokens,
      contextWindow: e.context.window, costUsd: e.cost?.usd,
      rateLimits: e.rateLimits.map(r => ({ kind: r.kind, percentUsed: r.percentUsed })),
    }))
    await showStatus($)
    return next(e)
  })

  // 모델 요청마다 실제 사용 토큰을 더한다(서브에이전트 요청 포함).
  on('turn.step', async function* ($, e, next) {
    const result = yield* next(e)
    const used = result.usage
    if (used) {
      await update($, tokens, t => ({
        input: t.input + used.input_tokens,
        output: t.output + used.output_tokens,
        cacheRead: t.cacheRead + used.cache_read_input_tokens,
        cacheWrite: t.cacheWrite + used.cache_creation_input_tokens,
        requests: t.requests + 1,
      }))
    }
    return result
  })

  // 주 대화의 턴이 끝날 때, 패널을 쓰는 중이면 진행률을 다시 읽는다(서브에이전트 턴은 건너뜀).
  on('turn.complete', async ($, e, next) => {
    const done = await next(e)
    if (!e.agentId && (await read($, active))) await refreshProgress($)
    return done
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Text } = $.ui.resolve(e)
    const p = await read($, progress)
    const u = await read($, usage)
    const t = await read($, tokens)
    const room = Math.max(3, (e.viewport?.rows ?? 30) - 22)

    return (
      <Box flexDirection="column" gap={1}>
        <Box flexDirection="column">
          <Text bold>SAST 조치 진행</Text>
          {p.kind === 'none' && <Text dimColor>{p.reason}</Text>}
          {p.kind === 'error' && <Text color="error">읽기 실패: {p.message}</Text>}
          {p.kind === 'ok' && (
            <Box flexDirection="column">
              <Text>
                <Text color="success">{bar(percent(p.verified, p.total))}</Text> {percent(p.verified, p.total)}%
              </Text>
              <Text>완료(verified) {p.verified} / 전체 {p.total} · 남음 {p.total - p.verified} · 보류 {p.deferred}</Text>
              <Text dimColor>
                {Object.entries(p.byStatus).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(' · ')}
              </Text>
              <Text bold>체커별 (남은 순)</Text>
              {p.checkers.slice(0, room).map(c => (
                <Text>
                  {bar(percent(c.verified, c.total), 10)} {c.verified}/{c.total} {c.code}
                </Text>
              ))}
              {p.checkers.length > room && <Text dimColor>외 {p.checkers.length - room}개 체커</Text>}
              <Text dimColor>갱신 {clockText(p.checkedAt)} · 턴이 끝날 때마다, /sast-progress로 즉시</Text>
            </Box>
          )}
        </Box>
        <Box flexDirection="column">
          <Text bold>토큰 · 비용</Text>
          <Text>
            컨텍스트 {u.contextPercent === undefined ? '-' : `${Math.round(u.contextPercent)}%`} ({compact(u.contextTokens)} / {compact(u.contextWindow)})
          </Text>
          <Text>
            이 세션 누적: 입력 {compact(t.input)} · 출력 {compact(t.output)} · 캐시 읽기 {compact(t.cacheRead)} · 캐시 쓰기 {compact(t.cacheWrite)}
          </Text>
          <Text dimColor>모델 요청 {t.requests}회 (서브에이전트 포함, 세션이 시작된 뒤부터)</Text>
          <Text>비용 {u.costUsd === undefined ? '-' : `$${u.costUsd.toFixed(2)}`}</Text>
          {u.rateLimits.map(r => (
            <Text>
              사용 한도 {r.kind}: {bar(r.percentUsed, 10)} {Math.round(r.percentUsed)}%
            </Text>
          ))}
        </Box>
      </Box>
    )
  })
}
