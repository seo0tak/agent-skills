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
  by: { workflowStatus: { analyzed: 3, 'change-complete': 2, verified: 15, deferred: 1, 'in-progress': 1 } },
  byChecker: {},
})

// 1.15.0 이전 툴킷: summary에 byChecker가 없고, 패널이 짧은 스크립트(python -c)로 데이터 파일을 센다.
const COUNTED = JSON.stringify({
  XSS: { total: 1, verified: 1, deferred: 0, remaining: 0 },
  SQL_INJECTION: { total: 3, verified: 1, deferred: 0, remaining: 2 },
})

type Seen = { opened: number; status: string[]; argv0: string[] }

// 엔진을 대신하는 훅. hasToolkit이 거짓이면 프로젝트에 툴킷 복사본이 없는 상태, minRisk가 null이면 처리 범위 미설정.
const STORE_ALIAS = 'Python was not found; run without arguments to install from the Microsoft Store, or disable this shortcut from Settings > Apps > Advanced app settings > App execution aliases.'

function engine(on: any, seen: Seen, hasToolkit: boolean, minRisk: string | null, windows = false, oldToolkit = false, noCheckers = false) {
  on('command.register', () => ({ value: { command: 'sast-progress' } }))
  on('ui.open', () => { seen.opened += 1; return { value: { isPlaced: true } } })
  on('ui.status', (_: unknown, e: { text?: string }) => { seen.status.push(String(e.text)); return { value: {} } })
  on('ui.toast', () => ({ value: {} }))
  on('clock.now', () => ({ value: 1_700_000_000_000 }))
  on('session.usage', () => ({
    value: {
      startedAt: 0,
      context: { tokens: 412_300, window: 1_000_000, percent: 41 },
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
    if (e.argv.includes('-c')) return { value: { exitCode: 0, stdout: oldToolkit ? COUNTED : '{}', stderr: '' } }
    const summary = e.argv.includes('in-scope') ? IN_SCOPE : ALL
    const older = oldToolkit || noCheckers
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
    expect((await ui.find({ type: 'Text', text: /처리 범위/ }))?.text).toContain(`위험도 높음 이상${sep}남음 7${sep}📦 전체 29 / 48`)
    expect((await ui.find({ type: 'Text', text: /^💤 3 보류$/ }))?.text).toBeTruthy() // 아이콘 범례(전체 기준)
    expect((await ui.find({ type: 'Text', text: /🔴 SQL_INJECTION/ }))?.text).toBeTruthy() // 남은 7건은 빨강 신호
    expect((await ui.find({ type: 'Text', text: surface === 'terminal' ? /남음 7 +5\/12/ : /남음 7 · 5\/12/ }))?.text).toBeTruthy()
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

  await ui.press({ key: 'tab-scope' })
  expect((await ui.find({ type: 'Text', text: /범위 안 22/ }))?.text).toBe('📦 범위 안 22, 그 밖 26')
  expect((await ui.find({ type: 'Text', text: /2건, 미확인/ }))?.text).toBeTruthy()
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
  expect((await ui.find({ type: 'Text', text: /🟡 SQL_INJECTION.*남음 2 +1\/3/ }))?.text).toBeTruthy()
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
  const at = (bodyColumns: number) => $.ui.mount({ ...PANE, surface: 'terminal', props: { ...PANE.props, bodyColumns } })

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
