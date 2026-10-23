import { expect, test } from 'claude-code/testing'

const PANE = {
  plugin: 'sast-remediation',
  component: 'Pane',
  requestId: 'sast-progress',
  props: {
    title: 'SAST 진행률 · 토큰',
    isFocused: false,
    bodyColumns: 60,
    placement: 'dock',
    scroll: { offset: 0, bodyRows: 40 },
    view: {},
  },
} as const

const SUMMARY = JSON.stringify({
  total: 4,
  by: { workflowStatus: { verified: 1, deferred: 1, analyzed: 2 } },
  byChecker: {
    SQLI: { total: 3, verified: 1, deferred: 0, remaining: 2, workflowStatus: {} },
    XSS: { total: 1, verified: 0, deferred: 1, remaining: 1, workflowStatus: {} },
  },
})

// 엔진을 대신하는 훅. hasToolkit이 거짓이면 프로젝트에 툴킷 복사본이 없는 상태다.
function engine(on: any, hasToolkit: boolean, seen: { opened: number; status: string[] }) {
  on('command.register', () => ({ value: { command: 'sast-progress' } }))
  on('ui.open', () => { seen.opened += 1; return { value: { isPlaced: true } } })
  on('ui.status', (_: unknown, e: { text?: string }) => { seen.status.push(String(e.text)); return { value: {} } })
  on('clock.now', () => ({ value: 1_700_000_000_000 }))
  on('session.usage', () => ({
    value: {
      startedAt: 0,
      context: { tokens: 50_000, window: 200_000, percent: 25 },
      rateLimits: [{ kind: 'five_hour', percentUsed: 12 }],
      cost: { usd: 1.5 },
    },
  }))
  on('fs.exists', () => ({ value: hasToolkit }))
  on('process.run', () => ({ value: { exitCode: 0, stdout: SUMMARY, stderr: '' } }))
  on('skill.prompt', (_: unknown, e: { text: string }) => ({ text: e.text }))
  on('session.start', (_: unknown, e: { cwd: string }) => ({ cwd: e.cwd }))
}

test('a project with the toolkit opens the pane and shows progress and tokens', async ($, on) => {
  const seen = { opened: 0, status: [] as string[] }
  engine(on, true, seen)
  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  expect(seen.opened).toBe(1)
  expect(seen.status.at(-1)).toBe('SAST 25% (1/4) · ctx 25% · $1.50')

  for (const surface of ['terminal', 'desktop'] as const) {
    const ui = await $.ui.mount({ ...PANE, surface })
    expect((await ui.find({ type: 'Text', text: /완료\(verified\) 1 \/ 전체 4/ }))?.text).toBeTruthy()
    expect((await ui.find({ type: 'Text', text: /SQLI/ }))?.text).toContain('1/3')
    expect((await ui.find({ type: 'Text', text: /컨텍스트 25%/ }))?.text).toContain('50.0k / 200.0k')
    expect((await ui.find({ type: 'Text', text: /^비용 / }))?.text).toBe('비용 $1.50')
    await ui.unmount()
  }
})

test('without the toolkit nothing shows until the skill runs', async ($, on) => {
  const seen = { opened: 0, status: [] as string[] }
  engine(on, false, seen)
  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  expect(seen.opened).toBe(0)
  expect(seen.status).toEqual([])

  await $.skill.prompt({ skill: 'other-skill', text: '' })
  expect(seen.opened).toBe(0)

  await $.skill.prompt({ skill: 'sast-remediation:sast-remediation', text: '' })
  expect(seen.opened).toBe(1)
  expect(seen.status.at(-1)).toBe('SAST 준비 전 · ctx 25% · $1.50')
  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  expect((await ui.find({ type: 'Text', text: /sast-remediation-toolkit/ }))?.text).toBeTruthy()
  await ui.unmount()
})
