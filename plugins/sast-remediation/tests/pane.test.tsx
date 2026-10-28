import { expect, test } from 'claude-code/testing'

const PANE = {
  plugin: 'sast-remediation',
  component: 'Pane',
  requestId: 'sast-progress',
  props: {
    title: 'SAST 진행률',
    isFocused: false,
    bodyColumns: 60,
    placement: 'dock',
    scroll: { offset: 0, bodyRows: 40 },
    view: {},
  },
} as const

const ALL = JSON.stringify({
  total: 48,
  by: {
    workflowStatus: { todo: 3, analyzed: 7, 'change-complete': 6, verified: 29, deferred: 3 },
    risk: { high: 22, medium: 18, low: 6, unknown: 2 },
  },
  byChecker: {
    SQL_INJECTION: { total: 12, verified: 5, deferred: 1, remaining: 7 },
    XSS_REFLECTED: { total: 10, verified: 6, deferred: 0, remaining: 4 },
    'FORBIDDEN.LOCAL_STORAGE_ACCESS': { total: 3, verified: 0, deferred: 0, remaining: 3 },
  },
})
const IN_SCOPE = JSON.stringify({
  total: 22,
  by: {
    workflowStatus: { analyzed: 3, 'change-complete': 2, verified: 15, deferred: 1, 'in-progress': 1 },
    conclusion: { fix: 14, 'false-positive': 5, 'needs-review': 2, unreviewed: 1 },
  },
  byChecker: {
    SQL_INJECTION: { total: 8, verified: 5, deferred: 1, remaining: 3 },
    XSS_REFLECTED: { total: 6, verified: 6, deferred: 0, remaining: 0 },
  },
})

// 1.15.0 이전 툴킷: summary에 byChecker가 없고, 패널이 짧은 스크립트(python -c)로 데이터 파일을 센다.
const COUNTED = JSON.stringify({
  all: {
    XSS: { total: 1, verified: 1, deferred: 0, remaining: 0 },
    SQL_INJECTION: { total: 3, verified: 1, deferred: 0, remaining: 2 },
  },
  scope: { SQL_INJECTION: { total: 2, verified: 1, deferred: 0, remaining: 1 } },
})

// 체커 10개(남은 건수 10, 9, …, 1 순)
const MANY = JSON.stringify({
  ...JSON.parse(ALL),
  byChecker: Object.fromEntries(Array.from({ length: 10 }, (_, i) =>
    [`CHECKER_${String(i + 1).padStart(2, '0')}`, { total: 10 - i, verified: 0, deferred: 0, remaining: 10 - i }])),
})

type Seen = { opened: number; status: string[]; argv0: string[]; engineScrolls?: number; countArg?: string }

// 엔진을 대신하는 훅. hasToolkit이 거짓이면 프로젝트에 툴킷 복사본이 없는 상태, minRisk가 null이면 처리 범위 미설정.
const STORE_ALIAS = 'Python was not found; run without arguments to install from the Microsoft Store, or disable this shortcut from Settings > Apps > Advanced app settings > App execution aliases.'

function engine(on: any, seen: Seen, hasToolkit: boolean, minRisk: string | null, windows = false, oldToolkit = false, noCheckers = false, many = false, byChecker?: object) {
  on('command.register', () => ({ value: { command: 'sast-progress' } }))
  on('ui.open', () => { seen.opened += 1; return { value: { isPlaced: true } } })
  on('ui.status', (_: unknown, e: { text?: string }) => { seen.status.push(String(e.text)); return { value: {} } })
  on('ui.toast', () => ({ value: {} }))
  on('ui.scroll', () => { seen.engineScrolls = (seen.engineScrolls ?? 0) + 1; return { value: {} } }) // 엔진이 패널 전체를 움직임
  on('clock.now', () => ({ value: 1_700_000_000_000 }))
  on('session.usage', (_: unknown, e?: { breakdown?: string }) => ({
    value: {
      startedAt: 0,
      context: {
        tokens: 412_300, window: 1_000_000, percent: 41,
        // 구성은 breakdown을 물었을 때만 온다
        ...(e?.breakdown ? { breakdown: { totalTokens: 412_300, maxTokens: 1_000_000, categories: [
          { name: 'System prompt', tokens: 3_100, color: 'promptBorder', isDeferred: false, kind: 'used' },
          { name: 'System tools', tokens: 21_400, color: 'inactive', isDeferred: false, kind: 'used' },
          { name: 'Messages', tokens: 387_800, color: 'permission', isDeferred: false, kind: 'used' },
          { name: 'MCP tools', tokens: 9_000, color: 'claude', isDeferred: true, kind: 'deferred' },
          { name: 'Free space', tokens: 547_700, color: 'inactive', isDeferred: false, kind: 'free' },
          { name: 'Autocompact buffer', tokens: 40_000, color: 'inactive', isDeferred: false, kind: 'buffer' },
        ] } } : {}),
      },
      rateLimits: [{ kind: 'five_hour', percentUsed: 37 }],
      cost: { usd: 18.42 },
    },
  }))
  on('fs.exists', () => ({ value: hasToolkit }))
  on('fs.read', () => ({ value: JSON.stringify({ processingScope: minRisk ? { minRisk } : undefined }) }))
  on('process.run', (_: unknown, e: { argv: string[] }) => {
    seen.argv0.push(e.argv[0] ?? '')
    // Windows: python3는 Store 바로가기라 9009로 끝나고, py -3이 실제 파이썬이다.
    if (windows && e.argv[0] === 'python3') return { value: { exitCode: 9009, stdout: '', stderr: STORE_ALIAS } }
    if (windows && e.argv[0] === 'python') throw new Error('spawn python ENOENT')
    if (e.argv.includes('-c')) {
      seen.countArg = e.argv.at(-1) // 집계 스크립트에 넘긴 최소 위험도
      return { value: { exitCode: 0, stdout: oldToolkit ? COUNTED : '{"all": {}, "scope": {}}', stderr: '' } }
    }
    const summary = e.argv.includes('in-scope') ? IN_SCOPE : ALL
    const older = oldToolkit || noCheckers
    if (byChecker) return { value: { exitCode: 0, stdout: JSON.stringify({ ...JSON.parse(summary), byChecker }), stderr: '' } }
    if (many && !e.argv.includes('in-scope')) return { value: { exitCode: 0, stdout: MANY, stderr: '' } }
    return { value: { exitCode: 0, stdout: older ? JSON.stringify({ ...JSON.parse(summary), byChecker: undefined }) : summary, stderr: '' } }
  })
  on('skill.prompt', (_: unknown, e: { text: string }) => ({ text: e.text }))
  on('session.start', (_: unknown, e: { cwd: string }) => ({ cwd: e.cwd }))
}

test('the summary card leads with the in-scope completion and both surfaces draw it', async ($, on) => {
  const seen: Seen = { opened: 0, status: [], argv0: [] }
  engine(on, seen, true, 'high')
  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  expect(seen.opened).toBe(1)
  expect(seen.status.at(-1)).toBe('SAST 15/22 범위, 29/48 전체 | ctx 41% | $18.42')

  for (const [surface, sep] of [['terminal', ', '], ['desktop', ' · ']] as const) {
    const ui = await $.ui.mount({ ...PANE, surface })
    expect((await ui.find({ type: 'Text', text: /🔍 SAST 진행률   68%  15 \/ 22/ }))?.text).toBeTruthy() // 머리 띠, 왼쪽 정렬
    expect((await ui.find({ type: 'Text', text: /처리 범위/ }))?.text).toContain(`위험도 높음 이상${sep}남음 7${sep}전체 29 / 48`)
    expect((await ui.find({ type: 'Text', text: /^💤 1 보류$/ }))?.text).toBeTruthy() // 범례도 범위 안 기준
    // 체커 목록도 기본은 범위 안. 신호등은 목록 안 최대 남은 건수 대비
    expect((await ui.find({ type: 'Text', text: /^범위 안 체커 2개/ }))?.text).toBeTruthy()
    expect((await ui.find({ type: 'Text', text: /🔴 SQL_INJECTION/ }))?.text).toBeTruthy()
    expect((await ui.find({ type: 'Text', text: /🟢 XSS_REFLECTED/ }))?.text).toBeTruthy()
    expect((await ui.find({ type: 'Text', text: surface === 'terminal' ? /남음 3 +5\/8/ : /남음 3 · 5\/8/ }))?.text).toBeTruthy()
    await ui.press({ key: 'checker-view' }) // v: 전체 보기
    expect((await ui.find({ type: 'Text', text: /^전체 체커 3개/ }))?.text).toBeTruthy()
    expect((await ui.find({ type: 'Text', text: surface === 'terminal' ? /남음 7 +5\/12/ : /남음 7 · 5\/12/ }))?.text).toBeTruthy()
    await ui.press({ key: 'checker-view' })
    expect((await ui.find({ type: 'Text', text: /^ 1 📋 체커 $/ }))?.text).toBeTruthy() // 지금 탭은 반전 알약
    expect((await ui.find({ type: 'Button', text: /🧠 토큰/ }))).toBeTruthy()
    expect((await ui.find({ type: 'Text', text: /🕒 .*갱신/ }))?.text).toContain('$18.42') // 바닥 줄
    await ui.unmount()
  }
})

test('the tabs switch to tokens and scope', async ($, on) => {
  const seen: Seen = { opened: 0, status: [], argv0: [] }
  engine(on, seen, true, 'high')
  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })

  await ui.press({ key: 'tab-tokens' })
  expect((await ui.find({ type: 'Text', text: /🧠 컨텍스트 41%/ }))?.text).toContain('412.3k / 1.00M')
  expect((await ui.find({ type: 'Text', text: /이번 세션 비용/ }))?.text).toContain('$18.42')
  expect((await ui.find({ type: 'Text', text: /^ {2} 대화 387\.8k 39%$/ }))?.text).toBeTruthy() // 이름은 한글로, 가로 범례
  expect((await ui.find({ type: 'Text', text: /시스템 프롬프트 3\.1k <1%/ }))?.text).toBeTruthy() // 1% 미만은 <1%
  expect((await ui.find({ type: 'Text', text: /압축 예비/ }))?.text).toBeTruthy()
  expect(await ui.find({ type: 'Text', text: /MCP 도구/ })).toBeUndefined() // 지연 로드 도구는 뺀다

  await ui.press({ key: 'tab-scope' })
  expect((await ui.find({ type: 'Text', text: /범위 안 22/ }))?.text).toBe('기준: 위험도 높음 이상, 범위 안 22, 그 밖 26')
  expect((await ui.find({ type: 'Text', text: /2건, 미확인/ }))?.text).toBeTruthy()
  expect((await ui.find({ type: 'Text', text: /전체 작업 단계/ }))?.text).toContain('29 / 48 검증 완료') // 요약이 범위 기준이라 여기는 전체
  expect((await ui.find({ type: 'Text', text: /^💤 3 보류$/ }))?.text).toBeTruthy()
  expect(await ui.find({ type: 'Text', text: /^🔎 3 분석$/ })).toBeUndefined() // 요약은 한 줄로 접힘
  expect((await ui.find({ type: 'Text', text: /^수정 필요 .*14건$/ }))?.text).toBeTruthy()
  expect((await ui.find({ type: 'Text', text: /^미검토 .*1건$/ }))?.text).toBeTruthy()
  await ui.unmount()
})

test('without a processing scope the card counts everything', async ($, on) => {
  const seen: Seen = { opened: 0, status: [], argv0: [] }
  engine(on, seen, true, null)
  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  expect(seen.status.at(-1)).toBe('SAST 29/48 | ctx 41% | $18.42')
  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  expect((await ui.find({ type: 'Text', text: /^29 \/ 48/ }))?.text).toContain('60%')
  await ui.press({ key: 'tab-scope' })
  expect((await ui.find({ type: 'Text', text: /처리 범위가 아직 정해지지 않았습니다/ }))?.text).toBeTruthy()
  await ui.unmount()
})

test('without the toolkit nothing shows until the skill runs', async ($, on) => {
  const seen: Seen = { opened: 0, status: [], argv0: [] }
  engine(on, seen, false, null)
  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  expect(seen.opened).toBe(0)
  expect(seen.status).toEqual([])

  await $.skill.prompt({ skill: 'other-skill', text: '' })
  expect(seen.opened).toBe(0)

  await $.skill.prompt({ skill: 'sast-remediation:sast-remediation', text: '' })
  expect(seen.opened).toBe(1)
  expect(seen.status.at(-1)).toBe('SAST 준비 전 | ctx 41% | $18.42')
  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  expect((await ui.find({ type: 'Text', text: /sast-remediation-toolkit/ }))?.text).toBeTruthy()
  await ui.unmount()
})

test('on Windows the panel falls back from the Store alias to py -3', async ($, on) => {
  const seen: Seen = { opened: 0, status: [], argv0: [] }
  engine(on, seen, true, 'high', true)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  expect(seen.status.at(-1)).toBe('SAST 15/22 범위, 29/48 전체 | ctx 41% | $18.42')
  expect(seen.argv0.slice(0, 3)).toEqual(['python3', 'python', 'py'])
  expect(seen.argv0.at(-1)).toBe('py') // 찾은 뒤에는 py로 바로 간다
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await ui.find({ type: 'Text', text: /Python was not found/ })).toBeUndefined()
  await ui.unmount()
})

// 폭이 모호한 문자(·, ●, █, ░, │, 상자 테두리 등)는 한글 글꼴 터미널에서 두 칸으로 그려져 줄이 잘린다.
const AMBIGUOUS = /[\u00A1-\u00BF\u2010-\u2027\u2030-\u203E\u2190-\u21FF\u2460-\u24FF\u2500-\u257F\u2580-\u259F\u25A0-\u25FF\u2600-\u26FF]/

function strings(node: unknown, out: string[] = []): string[] {
  if (typeof node === 'string') out.push(node)
  else if (Array.isArray(node)) node.forEach(n => strings(n, out))
  else if (node && typeof node === 'object') {
    const value = node as Record<string, unknown>
    for (const key of ['children', 'label', 'props']) if (key in value) strings(value[key], out)
  }
  return out
}

test('the terminal drawing uses no ambiguous-width characters and no borders', async ($, on) => {
  const seen: Seen = { opened: 0, status: [], argv0: [] }
  engine(on, seen, true, 'high')
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  for (const key of ['tab-tokens', 'tab-scope', 'tab-checkers']) {
    await ui.press({ key })
    const tree = await ui.drawn()
    const text = strings(tree).join('')
    expect(text.match(AMBIGUOUS)).toBeNull()
    // ASCII·한글 밖의 문자는 항상 두 칸인 그림 문자(Emoji_Presentation)만. FE0F 변형 선택자도 쓰지 않는다.
    expect([...text].filter(ch => ch > '\u007e' && !/[\uac00-\ud7a3]/.test(ch) && !/\p{Emoji_Presentation}/u.test(ch))).toEqual([])
    expect(text.includes('\ufe0f')).toBe(false)
    expect(JSON.stringify(tree)).not.toContain('"borderStyle"')
  }
  expect(seen.status.at(-1)?.match(AMBIGUOUS)).toBeFalsy()
  await ui.unmount()
})

test('with an older toolkit the checker tab counts the data files', async ($, on) => {
  const seen: Seen = { opened: 0, status: [], argv0: [] }
  engine(on, seen, true, 'high', false, true)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(seen.countArg).toBe('high') // 범위 안도 같은 스크립트가 최소 위험도로 센다
  expect((await ui.find({ type: 'Text', text: /🔴 SQL_INJECTION.*남음 1 +1\/2/ }))?.text).toBeTruthy() // 범위 안
  await ui.press({ key: 'checker-view' })
  expect((await ui.find({ type: 'Text', text: /🔴 SQL_INJECTION.*남음 2 +1\/3/ }))?.text).toBeTruthy() // 전체: 집계 스크립트
  expect((await ui.find({ type: 'Text', text: /🟢 XSS.*남음 0 +1\/1/ }))?.text).toBeTruthy()
  await ui.unmount()
})

test('an empty checker list says so instead of drawing nothing', async ($, on) => {
  const seen: Seen = { opened: 0, status: [], argv0: [] }
  engine(on, seen, true, 'high', false, false, true)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect((await ui.find({ type: 'Text', text: /체커별 집계를 읽지 못했습니다/ }))?.text).toBeTruthy()
  await ui.unmount()
})

test('the checker rows follow the pane width', async ($, on) => {
  const seen: Seen = { opened: 0, status: [], argv0: [] }
  engine(on, seen, true, 'high')
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  const at = async (bodyColumns: number) => {
    const ui = await $.ui.mount({ ...PANE, surface: 'terminal', props: { ...PANE.props, bodyColumns } })
    if (!(await ui.find({ type: 'Text', text: /^전체 체커/ }))) await ui.press({ key: 'checker-view' })
    return ui
  }

  const wide = await at(120) // 넓으면 긴 체커 이름을 자르지 않고, 검증/전체도 보인다
  expect((await wide.find({ type: 'Text', text: /FORBIDDEN\.LOCAL_STORAGE_ACCESS .*남음 3 +0\/3/ }))?.text).toBeTruthy()
  await wide.unmount()

  const mid = await at(60) // 중간 폭은 이름을 ~로 줄인다
  expect((await mid.find({ type: 'Text', text: /FORBIDDEN\.LOCAL_STORAGE_A~/ }))?.text).toBeTruthy()
  await mid.unmount()

  const narrow = await at(40) // 좁으면 막대와 검증/전체를 뺀다
  const row = (await narrow.find({ type: 'Text', text: /SQL_INJECTION/ }))?.text ?? ''
  expect(row).toMatch(/남음 7$/)
  expect(row).not.toMatch(/5\/12/)
  await narrow.unmount()
})

test('short checker codes narrower than the header still draw', async ($, on) => {
  const seen: Seen = { opened: 0, status: [], argv0: [] }
  engine(on, seen, true, 'high', false, false, false, false, { XSS: { total: 2, verified: 1, deferred: 0, remaining: 1 } })
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect((await ui.find({ type: 'Text', text: /XSS .*남음 1/ }))?.text).toBeTruthy()
  await ui.unmount()
})

test('a long checker list scrolls under a pinned header', async ($, on) => {
  const seen: Seen = { opened: 0, status: [], argv0: [] }
  engine(on, seen, true, 'high', false, false, false, true)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  // 높이 22줄: 고정 줄(띠·요약·탭·관점·열 제목·범례·바닥)을 뺀 체커 6줄 자리 중 한 줄은 위치 안내라 5개씩 보인다
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal', props: { ...PANE.props, scroll: { offset: 0, bodyRows: 22 } } })
  await ui.press({ key: 'checker-view' }) // 전체 10개
  const position = async () => (await ui.find({ type: 'Text', text: /개 체커, 휠이나 방향키로 스크롤/ }))?.text ?? ''
  expect(await position()).toMatch(/^1-5 \/ 10개 체커/)
  expect(await ui.find({ type: 'Text', text: /CHECKER_06/ })).toBeUndefined()

  const scroll = (by: number) => $.ui.scroll({ component: 'Pane', requestId: 'sast-progress', offset: 0, by,
    bodyRows: 22, contentRows: 22, origin: { kind: 'person' } } as any)
  await scroll(1) // 휠 한 칸
  await ui.redraw()
  expect(await position()).toMatch(/^2-6 \/ 10개 체커.*Home 맨 위/)
  expect((await ui.find({ type: 'Text', text: /CHECKER_06/ }))?.text).toBeTruthy()
  expect(await ui.find({ type: 'Text', text: /CHECKER_01/ })).toBeUndefined()

  await scroll(30) // 끝을 넘으면 마지막에 멈춘다(End)
  await ui.redraw()
  expect(await position()).toMatch(/^6-10 \/ 10개 체커/)
  await scroll(-22) // Home
  await ui.redraw()
  expect(await position()).toMatch(/^1-5 \/ 10개 체커/)

  expect(seen.engineScrolls ?? 0).toBe(0) // 체커 탭의 스크롤은 목록이 받는다
  await ui.press({ key: 'tab-tokens' }) // 다른 탭에서는 엔진이 패널 전체를 스크롤한다
  await scroll(1)
  expect(seen.engineScrolls).toBe(1)
  await ui.unmount()
})
