import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type { Counts, PaneTab, ProgressView, ScopeCounts, TokenTotals, UsageView } from '../types'

// Claude Code 전용 진행률 패널. 프로젝트에 툴킷 복사본이 있거나 이 스킬이 실행되면 열린다.
// 진행률은 툴킷의 query --summary(읽기 전용)를 그대로 보여 줄 뿐 상태를 바꾸지 않는다.
// 배치: 위에 요약 카드(완료율·칩·작업 단계), 아래 탭(체커 · 토큰 · 범위).
const TOOLKIT = 'sast-remediation-toolkit'
const PANE = 'sast-progress'
const TITLE = 'SAST 진행률'
const REFRESH_GAP_MS = 5000
const STALE_MS = 120_000
const SKILL_NAME = /(^|:)sast-remediation$/

const progress = atom({ plugin: 'sast-remediation', key: 'progress' } as const,
  { kind: 'none', reason: '아직 확인하지 않았습니다.' } as ProgressView)
const usage = atom({ plugin: 'sast-remediation', key: 'usage' } as const, { rateLimits: [] } as UsageView)
const tokens = atom({ plugin: 'sast-remediation', key: 'tokens' } as const,
  { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, requests: 0 } as TokenTotals)
// 이 세션에서 패널을 쓰는지: 툴킷이 있거나 스킬이 실행됐을 때만 참. 그 전에는 화면에 아무것도 내지 않는다.
const active = atom({ plugin: 'sast-remediation', key: 'active' } as const, false)
const tab = atom({ plugin: 'sast-remediation', key: 'tab' } as const, 'checkers' as PaneTab)

// 작업 단계: 표시 순서·이름·색. 색은 의미에만 쓴다(완료 초록, 진행 파랑, 수정 완료 주황, 보류 보라).
const STAGES: { key: string; label: string; hex: string; theme: string }[] = [
  { key: 'todo', label: '시작 전', hex: '#8a8f99', theme: 'inactive' },
  { key: 'in-progress', label: '작업 중', hex: '#8fa8ff', theme: 'suggestion' },
  { key: 'analyzed', label: '분석', hex: '#5b7cf0', theme: 'suggestion' },
  { key: 'change-complete', label: '수정 완료', hex: '#d9962b', theme: 'warning' },
  { key: 'verified', label: '검증 완료', hex: '#2fa36b', theme: 'success' },
  { key: 'deferred', label: '보류', hex: '#8b6fd6', theme: 'merged' },
]
const RISK_ORDER = ['critical', 'very-high', 'high', 'medium', 'low']
const RISK_LABEL: Record<string, string> = {
  critical: '긴급', 'very-high': '매우 높음', high: '높음', medium: '보통', low: '낮음', info: '정보', unknown: '미확인',
}
const TRACK = 'rgba(128,128,128,0.28)'
const OK = '#2fa36b'
const WARN = '#d9962b'
const BAD = '#d4483f'
const BLUE = '#5b7cf0'

type Summary = {
  total: number
  by: { workflowStatus: Record<string, number>; risk?: Record<string, number> }
  byChecker: Record<string, { total: number; verified: number; deferred: number; remaining: number }>
}

let lastRefresh = 0
// 툴킷을 돌릴 파이썬. Windows에는 python3가 없거나 Microsoft Store 바로가기라 python, py -3도 차례로 시도한다.
const PYTHONS: string[][] = [['python3'], ['python'], ['py', '-3']]
let python: string[] | null = null
// 실행 파일이 아예 없으면 process.run이 실패하고, Windows의 Store 바로가기는 9009와 이 문구로 끝난다.
// 툴킷 자체의 오류(예: 파일 없음)는 다음 후보로 넘기지 않고 그대로 보여 준다.
const NOT_FOUND = /Python was not found|is not recognized as an internal or external command/i

async function runToolkit($: EngineInterface, args: string[]) {
  const candidates = python ? [python, ...PYTHONS.filter(c => c.join(' ') !== python!.join(' '))] : PYTHONS
  for (const candidate of candidates) {
    let run
    try {
      run = await $.process.run([...candidate, '-B', 'tools/sast_toolkit.py', ...args], { cwd: TOOLKIT, timeoutMs: 20000 })
    } catch {
      continue // 실행 파일이 없어 시작하지 못함
    }
    const text = `${run.stderr}\n${run.stdout}`
    if (run.exitCode !== 0 && (run.exitCode === 9009 || NOT_FOUND.test(text))) continue
    python = candidate
    return run
  }
  throw new Error('Python 3을 찾지 못했습니다(python3, python, py -3을 시도함). Python 3을 설치하고 PATH에 추가해 주세요.')
}

function counts(summary: Summary): Counts {
  const byStatus = summary.by?.workflowStatus ?? {}
  return {
    total: summary.total,
    verified: byStatus.verified ?? 0,
    deferred: byStatus.deferred ?? 0,
    inProgress: byStatus['in-progress'] ?? 0,
    byStatus,
  }
}

export function parseSummary(stdout: string, checkedAt: number, scoped: string | null = null,
  minRisk: string | null = null): ProgressView {
  const summary = JSON.parse(stdout) as Summary
  const checkers = Object.entries(summary.byChecker ?? {}).map(([code, c]) => ({
    code, total: c.total, verified: c.verified, remaining: c.remaining,
  }))
  const scope: ScopeCounts | null = scoped && minRisk
    ? { ...counts(JSON.parse(scoped) as Summary), minRisk }
    : null
  return { kind: 'ok', all: counts(summary), scope, risk: summary.by?.risk ?? {}, checkers, checkedAt }
}

// byChecker가 없는 옛 툴킷(1.15.0 이전)용: query 행에서 체커별 진행을 직접 센다(대시보드와 같은 정의).
export function checkersFromRows(stdout: string) {
  const rows = JSON.parse(stdout) as { checker?: { code?: string }; progress?: { workflowStatus?: string } }[]
  const by = new Map<string, { code: string; total: number; verified: number; remaining: number }>()
  for (const row of Array.isArray(rows) ? rows : []) {
    const code = row.checker?.code || 'unknown'
    const entry = by.get(code) ?? { code, total: 0, verified: 0, remaining: 0 }
    entry.total += 1
    if (row.progress?.workflowStatus === 'verified') entry.verified += 1
    entry.remaining = entry.total - entry.verified
    by.set(code, entry)
  }
  return [...by.values()].sort((a, b) => b.remaining - a.remaining || b.total - a.total || a.code.localeCompare(b.code))
}

async function minRiskOf($: EngineInterface): Promise<string | null> {
  try {
    const profile = JSON.parse(await $.fs.read(`${TOOLKIT}/data/project-profile.json`)) as
      { processingScope?: { minRisk?: string } }
    return profile.processingScope?.minRisk ?? null
  } catch {
    return null
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
    view = { kind: 'none', reason: '아직 검출이 등록되지 않았습니다. 입력 확인(00)과 초기 분석(01)이 끝나면 표시됩니다.' }
  } else {
    try {
      const run = await runToolkit($, ['query', '--summary'])
      if (run.exitCode !== 0) {
        throw new Error((run.stderr || run.stdout).trim().split('\n')[0] || `종료 코드 ${run.exitCode}`)
      }
      const minRisk = await minRiskOf($)
      let scoped: string | null = null
      if (minRisk) {
        const inScope = await runToolkit($, ['query', '--summary', '--scope', 'in-scope'])
        scoped = inScope.exitCode === 0 ? inScope.stdout : null
      }
      view = parseSummary(run.stdout, now, scoped, minRisk)
      if (view.kind === 'ok' && view.checkers.length === 0 && view.all.total > 0) {
        const rows = await runToolkit($, ['query'])
        if (rows.exitCode === 0 && !rows.isStdoutTruncated) view = { ...view, checkers: checkersFromRows(rows.stdout) }
      }
    } catch (error) {
      const previous = await read($, progress)
      // 읽기에 실패해도 이전 값은 지우지 않는다. 화면에는 실패를 덧붙인다.
      view = previous.kind === 'ok'
        ? { ...previous }
        : { kind: 'error', message: error instanceof Error ? error.message : String(error), checkedAt: now }
      if (previous.kind === 'ok') await $.ui.toast(`SAST 진행률을 다시 읽지 못했습니다: ${String(error)}`)
    }
  }
  await update($, progress, () => view)
  await showStatus($)
}

async function activate($: EngineInterface) {
  await update($, active, () => true)
  await refreshProgress($, true)
  await $.ui.open({ id: PANE, title: TITLE, rows: 18 })
}

function percent(part: number, whole: number) {
  return whole > 0 ? Math.floor((part / whole) * 100) : 0
}

function compact(n?: number) {
  if (n === undefined) return '-'
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`
  return String(n)
}

function clockText(ms: number) {
  const d = new Date(ms)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function untilText(iso: string | undefined, now: number) {
  if (!iso) return ''
  const ms = Date.parse(iso) - now
  if (!Number.isFinite(ms) || ms <= 0) return ''
  const hours = Math.floor(ms / 3_600_000)
  return hours >= 1 ? `${hours}시간 뒤 초기화` : `${Math.max(1, Math.round(ms / 60_000))}분 뒤 초기화`
}

function contextColor(pct: number | undefined) {
  if (pct === undefined) return BLUE
  return pct >= 85 ? BAD : pct >= 70 ? WARN : BLUE
}

// ---- 그래픽(데스크톱 · VS Code · 모바일) ----
function ringSvg(pct: number) {
  const c = 2 * Math.PI * 26
  const done = (Math.min(100, Math.max(0, pct)) / 100) * c
  return `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">` +
    `<circle cx="32" cy="32" r="26" fill="none" stroke="${TRACK}" stroke-width="7"/>` +
    `<circle cx="32" cy="32" r="26" fill="none" stroke="${OK}" stroke-width="7" stroke-linecap="round" ` +
    `stroke-dasharray="${done.toFixed(1)} ${c.toFixed(1)}" transform="rotate(-90 32 32)"/></svg>`
}

function barSvg(parts: { value: number; hex: string }[], total: number, height = 8, ticks: number[] = []) {
  const width = 320
  let x = 0
  const rects = parts.filter(p => p.value > 0).map(p => {
    const w = total > 0 ? (p.value / total) * width : 0
    const r = `<rect x="${x.toFixed(1)}" y="0" width="${w.toFixed(1)}" height="${height}" fill="${p.hex}"/>`
    x += w
    return r
  }).join('')
  const marks = ticks.map(t => `<rect x="${((t / 100) * width - 1).toFixed(1)}" y="0" width="2" height="${height}" fill="${t >= 85 ? BAD : WARN}"/>`).join('')
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">` +
    `<clipPath id="r"><rect width="${width}" height="${height}" rx="${height / 2}"/></clipPath>` +
    `<g clip-path="url(#r)"><rect width="${width}" height="${height}" fill="${TRACK}"/>${rects}</g>${marks}</svg>`
}

// ---- 글자(터미널) ----
// 터미널은 ·, ●, █, ░, │, 상자 테두리 같은 '폭이 모호한' 문자를 한글 글꼴(예: Windows)에서 두 칸으로
// 그리는데 엔진은 한 칸으로 센다. 그러면 줄이 계산보다 길어져 오른쪽이 잘리고 막대가 사라진다.
// 그래서 터미널 쪽은 ASCII 구분자와 색칠한 빈칸 막대만 쓰고 테두리를 두지 않는다.
const TERM_SEP = ', '
const GRAPHIC_SEP = ' · '

function cellsOf(pct: number, width: number) {
  const filled = Math.round((Math.min(100, Math.max(0, pct)) / 100) * width)
  return { filled, empty: Math.max(0, width - filled) }
}

async function showStatus($: EngineInterface) {
  if (!(await read($, active))) return
  const p = await read($, progress)
  const u = await read($, usage)
  const parts: string[] = []
  if (p.kind === 'ok') {
    parts.push(p.scope
      ? `SAST ${p.scope.verified}/${p.scope.total} 범위, ${p.all.verified}/${p.all.total} 전체`
      : `SAST ${p.all.verified}/${p.all.total}`)
  } else {
    parts.push('SAST 준비 전')
  }
  if (u.contextPercent !== undefined) parts.push(`ctx ${Math.round(u.contextPercent)}%`)
  if (u.costUsd !== undefined) parts.push(`$${u.costUsd.toFixed(2)}`)
  // 상태 줄은 모든 화면이 터미널처럼 그리므로 ASCII 구분자만 쓴다.
  await $.ui.status(parts.join(' | '))
}

function usageFrom(source: { context: { percent?: number; tokens?: number; window: number };
  rateLimits: readonly { kind: string; percentUsed: number; resetsAt?: string }[]; cost?: { usd: number } }): UsageView {
  return {
    contextPercent: source.context.percent, contextTokens: source.context.tokens,
    contextWindow: source.context.window, costUsd: source.cost?.usd,
    rateLimits: source.rateLimits.map(r => ({ kind: r.kind, percentUsed: r.percentUsed, resetsAt: r.resetsAt })),
  }
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    const started = await next(e)
    await $.command.register({ name: 'sast-progress', description: 'SAST 진행률과 토큰 사용량 패널을 열고 새로 고친다' })
    const now = await $.session.usage()
    await update($, usage, () => usageFrom(now))
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
    await update($, usage, () => usageFrom(e))
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
    const ui = $.ui.resolve(e)
    const { Box, Text, Button } = ui
    // 그래픽은 데스크톱 · VS Code · 모바일에서만. 터미널은 글자로 그린다. resolve가 돌려주는 표에는 터미널에도
    // Svg가 (빈 조각으로) 채워져 있으므로 표가 아니라 화면 종류로 가른다.
    const Svg = e.surface !== 'terminal' && 'Svg' in ui ? ui.Svg : null
    const sep = Svg ? GRAPHIC_SEP : TERM_SEP
    const p = await read($, progress)
    const u = await read($, usage)
    const t = await read($, tokens)
    const current = await read($, tab)
    const now = await $.clock.now()
    const columns = e.props?.bodyColumns ?? 40
    const barWidth = Math.max(10, Math.min(30, columns - 6))
    const rows = e.props?.scroll?.bodyRows ?? 24

    const setTab = (next: PaneTab) => () => update($, tab, () => next)

    // 막대: 그래픽은 Svg, 터미널은 색칠한 빈칸(어느 글꼴에서나 한 칸).
    const bar = (parts: { value: number; hex: string; theme: string }[], total: number, alt: string, height = 8) => {
      if (Svg) return <Svg source={barSvg(parts, total, height)} alt={alt} height={height} />
      let used = 0
      const segments = parts.map(part => {
        const cells = total > 0 ? Math.round((part.value / total) * barWidth) : 0
        const take = Math.min(cells, barWidth - used)
        used += take
        return take > 0 ? <Text backgroundColor={part.theme}>{' '.repeat(take)}</Text> : ''
      })
      return <Text>{segments}{used < barWidth ? <Text backgroundColor="inactive">{' '.repeat(barWidth - used)}</Text> : ''}</Text>
    }
    const pctBar = (pct: number, hex: string, theme: string, alt: string, height = 6) =>
      Svg
        ? <Svg source={barSvg([{ value: pct, hex }], 100, height)} alt={alt} height={height} />
        : (() => { const c = cellsOf(pct, barWidth)
            return <Text><Text backgroundColor={theme}>{' '.repeat(c.filled)}</Text><Text backgroundColor="inactive">{' '.repeat(c.empty)}</Text></Text> })()

    // 이름과 값: 그래픽은 양끝 정렬, 터미널은 왼쪽 정렬(폭 계산이 어긋나도 값이 잘리지 않게).
    const labelValue = (label: string, value: string, dimValue = false, key?: string) => Svg
      ? (
        <Box key={key} flexDirection="row" justifyContent="space-between" columnGap={2}>
          <Text wrap="truncate">{label}</Text><Text tabular dimColor={dimValue}>{value}</Text>
        </Box>
      )
      : <Text key={key} wrap="truncate"><Text dimColor>{label}</Text>  <Text dimColor={dimValue}>{value}</Text></Text>

    const header = (() => {
      if (p.kind !== 'ok') return <Text bold>SAST 조치 진행</Text>
      const stale = now - p.checkedAt > STALE_MS
      const when = `${clockText(p.checkedAt)} 갱신${stale ? `${sep}오래됨` : ''}`
      if (!Svg) {
        return <Text><Text bold>SAST 조치 진행</Text>  <Text dimColor={!stale} color={stale ? 'warning' : undefined}>{when}</Text></Text>
      }
      return (
        <Box flexDirection="row" justifyContent="space-between">
          <Text bold>SAST 조치 진행</Text>
          <Text dimColor={!stale} color={stale ? 'warning' : undefined}><Text color={stale ? 'warning' : 'success'}>●</Text> {when}</Text>
        </Box>
      )
    })()

    // ---- 요약 카드 ----
    const summaryCard = (() => {
      if (p.kind === 'none') return <Text dimColor wrap="wrap">{p.reason}</Text>
      if (p.kind === 'error') return <Text color="error" wrap="wrap">진행률을 읽지 못했습니다: {p.message}</Text>
      const main = p.scope ?? p.all
      const pct = percent(main.verified, main.total)
      const remaining = main.total - main.verified
      const headline = `${main.verified} / ${main.total}`
      const caption = p.scope
        ? `처리 범위(위험도 ${RISK_LABEL[p.scope.minRisk] ?? p.scope.minRisk} 이상) 검증 완료${sep}전체 ${p.all.verified} / ${p.all.total}`
        : '전체 검증 완료'
      const chips = (
        <Box flexDirection="row" columnGap={2} flexWrap="wrap">
          <Text>남음 {remaining}</Text>
          {main.deferred > 0 && <Text color="warning">보류 {main.deferred}</Text>}
          {main.inProgress > 0 && <Text color="suggestion">작업 중 {main.inProgress}</Text>}
        </Box>
      )
      const stages = STAGES.filter(s => (p.all.byStatus[s.key] ?? 0) > 0)
      const legend = <Text dimColor wrap="wrap">{stages.map(s => `${s.label} ${p.all.byStatus[s.key]}`).join(sep)}</Text>
      const stageBar = bar(stages.map(s => ({ value: p.all.byStatus[s.key] ?? 0, hex: s.hex, theme: s.theme })), p.all.total,
        `작업 단계: ${stages.map(s => `${s.label} ${p.all.byStatus[s.key]}`).join(', ')}`)
      if (Svg) {
        return (
          <Box flexDirection="column" gap={1} borderStyle="round" paddingX={1}>
            <Box flexDirection="row" columnGap={2} alignItems="center">
              <Svg source={ringSvg(pct)} alt={`완료 ${pct}%`} width={64} height={64} />
              <Box flexDirection="column">
                <Text size="heading" weight="bold" tabular>{headline}  <Text color="success">{pct}%</Text></Text>
                <Text dimColor size="footnote" wrap="wrap">{caption}</Text>
                {chips}
              </Box>
            </Box>
            {stageBar}
            {legend}
          </Box>
        )
      }
      return (
        <Box flexDirection="column" paddingLeft={1}>
          <Text><Text bold>{headline}</Text>  <Text color="success" bold>{pct}%</Text></Text>
          {pctBar(pct, OK, 'success', `완료 ${pct}%`)}
          <Text dimColor wrap="wrap">{caption}</Text>
          {chips}
          <Text> </Text>
          {stageBar}
          {legend}
        </Box>
      )
    })()

    // ---- 탭: 지금 탭은 대괄호로 표시(흐리게 하는 것만으로는 터미널에서 구분이 안 된다) ----
    const tabButton = (name: PaneTab, label: string, hotkey: string) => (
      <Button key={`tab-${name}`} label={current === name ? `[${label}]` : label} hotkey={hotkey} plain
        dimColor={current !== name} onPress={setTab(name)} />
    )
    const tabs = (
      <Box flexDirection="row" columnGap={2}>
        {tabButton('checkers', '체커', '1')}
        {tabButton('tokens', '토큰', '2')}
        {tabButton('scope', '범위', '3')}
      </Box>
    )

    const progressRow = (key: string, label: string, detail: string, pct: number, hex: string, theme: string) => (
      <Box key={key} flexDirection="column">
        {labelValue(label, detail, true)}
        {pctBar(pct, hex, theme, `${label} ${pct}%`, 5)}
      </Box>
    )

    const checkersTab = (() => {
      if (p.kind !== 'ok') return <Text dimColor>검출이 등록되면 체커별 진행이 보입니다.</Text>
      const room = Math.max(3, Math.min(8, Math.floor((rows - 14) / 2)))
      const shown = p.checkers.slice(0, room)
      const rest = p.checkers.slice(room)
      return (
        <Box flexDirection="column" gap={1}>
          {shown.map(c => progressRow(c.code, c.code, `남음 ${c.remaining}${sep}${c.verified}/${c.total}`,
            percent(c.verified, c.total), OK, 'success'))}
          {rest.length > 0 && (
            <Text dimColor>외 {rest.length}개 체커{sep}남음 {rest.reduce((sum, c) => sum + c.remaining, 0)}</Text>
          )}
        </Box>
      )
    })()

    const tokensTab = (() => {
      const ctx = u.contextPercent
      const incoming = t.input + t.cacheRead + t.cacheWrite
      const hit = incoming > 0 ? Math.round((t.cacheRead / incoming) * 100) : undefined
      const ctxTheme = (ctx ?? 0) >= 85 ? 'error' : (ctx ?? 0) >= 70 ? 'warning' : 'suggestion'
      const gauge = Svg
        ? <Svg source={barSvg([{ value: ctx ?? 0, hex: contextColor(ctx) }], 100, 10, [70, 85])}
            alt={`컨텍스트 ${ctx === undefined ? '알 수 없음' : `${Math.round(ctx)}%`}, 주의 70%, 위험 85%`} height={10} />
        : pctBar(ctx ?? 0, contextColor(ctx), ctxTheme, '컨텍스트')
      const limitTheme = (pct: number) => pct >= 85 ? 'error' : pct >= 70 ? 'warning' : 'suggestion'
      const limitHex = (pct: number) => pct >= 85 ? BAD : pct >= 70 ? WARN : BLUE
      return (
        <Box flexDirection="column" gap={1}>
          <Box flexDirection="column">
            <Text dimColor>컨텍스트 {ctx === undefined ? '-' : `${Math.round(ctx)}%`}{sep}{compact(u.contextTokens)} / {compact(u.contextWindow)}</Text>
            {gauge}
          </Box>
          <Box flexDirection="column">
            {labelValue('이번 세션 비용', u.costUsd === undefined ? '-' : `$${u.costUsd.toFixed(2)}`, false, 'cost')}
            {labelValue('입력, 출력', `${compact(t.input)}, ${compact(t.output)}`, false, 'io')}
            {labelValue('캐시 적중', hit === undefined ? '-' : `${hit}% (읽기 ${compact(t.cacheRead)})`, false, 'cache')}
            {labelValue('모델 요청', `${t.requests}회`, false, 'requests')}
          </Box>
          {u.rateLimits.length > 0 && (
            <Box flexDirection="column" gap={1}>
              {u.rateLimits.map(r => progressRow(`limit-${r.kind}`,
                r.kind === 'five_hour' ? '5시간 한도' : r.kind === 'seven_day' ? '7일 한도' : r.kind,
                `${Math.round(r.percentUsed)}%${untilText(r.resetsAt, now) ? `${sep}${untilText(r.resetsAt, now)}` : ''}`,
                r.percentUsed, limitHex(r.percentUsed), limitTheme(r.percentUsed)))}
            </Box>
          )}
          <Text dimColor wrap="wrap">토큰은 이 세션에서 패널이 켜진 뒤의 모델 요청을 서브에이전트까지 더한 값입니다.</Text>
        </Box>
      )
    })()

    const scopeTab = (() => {
      if (p.kind !== 'ok') return <Text dimColor>검출이 등록되면 위험도별 처리 범위가 보입니다.</Text>
      if (!p.scope) {
        return <Text dimColor wrap="wrap">처리 범위가 아직 정해지지 않았습니다. 초기 분석(01) 뒤 사용자가 최소 위험도를 고르면, 범위 안 완료를 따로 보여 줍니다.</Text>
      }
      const cut = RISK_ORDER.indexOf(p.scope.minRisk)
      const levels = [...RISK_ORDER, 'info', 'unknown'].filter(level => (p.risk[level] ?? 0) > 0)
      const where = (level: string) => {
        const index = RISK_ORDER.indexOf(level)
        if (index < 0) return level === 'info' ? '범위 밖' : '미확인'
        return cut >= 0 && index <= cut ? '범위 안' : '범위 밖'
      }
      const outside = p.all.total - p.scope.total
      return (
        <Box flexDirection="column" gap={1}>
          <Text>기준: 위험도 <Text bold>{RISK_LABEL[p.scope.minRisk] ?? p.scope.minRisk}</Text> 이상</Text>
          <Text tabular>범위 안 {p.scope.total}{sep}그 밖 {outside}</Text>
          <Box flexDirection="column">
            {levels.map(level => labelValue(RISK_LABEL[level] ?? level, `${p.risk[level]}건${sep}${where(level)}`,
              where(level) !== '범위 안', `risk-${level}`))}
          </Box>
          <Text dimColor wrap="wrap">범위 밖과 미확인 항목도 입력과 기록은 그대로 보존됩니다. 범위 안 완료를 전체 완료로 보지 않습니다.</Text>
        </Box>
      )
    })()

    return (
      <Box flexDirection="column" gap={1}>
        {header}
        {summaryCard}
        {tabs}
        {current === 'tokens' ? tokensTab : current === 'scope' ? scopeTab : checkersTab}
      </Box>
    )
  })
}
