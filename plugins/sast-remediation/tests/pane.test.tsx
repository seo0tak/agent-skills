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
  },
})
const IN_SCOPE = JSON.stringify({
  total: 22,
  by: { workflowStatus: { analyzed: 3, 'change-complete': 2, verified: 15, deferred: 1, 'in-progress': 1 } },
  byChecker: {},
})

type Seen = { opened: number; status: string[]; argv0: string[] }

// 엔진을 대신하는 훅. hasToolkit이 거짓이면 프로젝트에 툴킷 복사본이 없는 상태, minRisk가 null이면 처리 범위 미설정.
const STORE_ALIAS = 'Python was not found; run without arguments to install from the Microsoft Store, or disable this shortcut from Settings > Apps > Advanced app settings > App execution aliases.'

function engine(on: any, seen: Seen, hasToolkit: boolean, minRisk: string | null, windows = false) {
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
    return { value: { exitCode: 0, stdout: e.argv.includes('in-scope') ? IN_SCOPE : ALL, stderr: '' } }
  })
  on('skill.prompt', (_: unknown, e: { text: string }) => ({ text: e.text }))
  on('session.start', (_: unknown, e: { cwd: string }) => ({ cwd: e.cwd }))
}

test('the summary card leads with the in-scope completion and both surfaces draw it', async ($, on) => {
  const seen: Seen = { opened: 0, status: [], argv0: [] }
  engine(on, seen, true, 'high')
  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  expect(seen.opened).toBe(1)
  expect(seen.status.at(-1)).toBe('SAST 15/22 범위 · 29/48 전체 │ ctx 41% │ $18.42')

  for (const surface of ['terminal', 'desktop'] as const) {
    const ui = await $.ui.mount({ ...PANE, surface })
    expect((await ui.find({ type: 'Text', text: /^15 \/ 22/ }))?.text).toContain('68%')
    expect((await ui.find({ type: 'Text', text: /처리 범위\(위험도 높음 이상\)/ }))?.text).toContain('전체 29 / 48')
    expect((await ui.find({ type: 'Text', text: /^보류 1$/ }))?.text).toBe('보류 1')
    expect((await ui.find({ type: 'Text', text: /^SQL_INJECTION$/ }))?.text).toBe('SQL_INJECTION')
    expect((await ui.find({ type: 'Text', text: /남음 7 · 5\/12/ }))?.text).toBeTruthy()
    await ui.unmount()
  }
})

test('the tabs switch to tokens and scope', async ($, on) => {
  const seen: Seen = { opened: 0, status: [], argv0: [] }
  engine(on, seen, true, 'high')
  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })

  await ui.press({ key: 'tab-tokens' })
  expect((await ui.find({ type: 'Text', text: /^컨텍스트 41%/ }))?.text).toContain('412.3k / 1.00M')
  expect((await ui.find({ type: 'Text', text: /^\$18\.42$/ }))?.text).toBe('$18.42')

  await ui.press({ key: 'tab-scope' })
  expect((await ui.find({ type: 'Text', text: /^범위 안 22/ }))?.text).toBe('범위 안 22 · 그 밖 26')
  expect((await ui.find({ type: 'Text', text: /^2건 · 미확인$/ }))?.text).toBeTruthy()
  await ui.unmount()
})

test('without a processing scope the card counts everything', async ($, on) => {
  const seen: Seen = { opened: 0, status: [], argv0: [] }
  engine(on, seen, true, null)
  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  expect(seen.status.at(-1)).toBe('SAST 29/48 │ ctx 41% │ $18.42')
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
  expect(seen.status.at(-1)).toBe('SAST 준비 전 │ ctx 41% │ $18.42')
  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  expect((await ui.find({ type: 'Text', text: /sast-remediation-toolkit/ }))?.text).toBeTruthy()
  await ui.unmount()
})

test('on Windows the panel falls back from the Store alias to py -3', async ($, on) => {
  const seen: Seen = { opened: 0, status: [], argv0: [] }
  engine(on, seen, true, 'high', true)
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  expect(seen.status.at(-1)).toBe('SAST 15/22 범위 · 29/48 전체 │ ctx 41% │ $18.42')
  expect(seen.argv0.slice(0, 3)).toEqual(['python3', 'python', 'py'])
  expect(seen.argv0.at(-1)).toBe('py') // 찾은 뒤에는 py로 바로 간다
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await ui.find({ type: 'Text', text: /Python was not found/ })).toBeUndefined()
  await ui.unmount()
})
