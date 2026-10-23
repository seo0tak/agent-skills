export type Counts = {
  total: number
  verified: number
  deferred: number
  inProgress: number
  byStatus: Record<string, number>
  byConclusion: Record<string, number>
}

export type ScopeCounts = Counts & { minRisk: string }

export type ProgressView =
  | { kind: 'none'; reason: string }
  | { kind: 'error'; message: string; checkedAt: number }
  | {
      kind: 'ok'
      all: Counts
      // 처리 범위(최소 위험도)가 정해진 차수에서만 있다. 없으면 전체 기준으로만 그린다.
      scope: ScopeCounts | null
      risk: Record<string, number>
      checkers: { code: string; total: number; verified: number; remaining: number }[]
      checkedAt: number
    }

export type UsageView = {
  contextPercent?: number
  contextTokens?: number
  contextWindow?: number
  costUsd?: number
  rateLimits: { kind: string; percentUsed: number; resetsAt?: string }[]
  // /context와 같은 컨텍스트 구성(엔진의 로컬 추정). 지연 로드 도구는 뺀다.
  breakdown?: { name: string; tokens: number; color: string; kind: string }[]
}

export type TokenTotals = { input: number; output: number; cacheRead: number; cacheWrite: number; requests: number }

export type PaneTab = 'checkers' | 'tokens' | 'scope'

declare module 'claude-code' {
  interface PluginState {
    'sast-remediation': {
      progress: ProgressView
      usage: UsageView
      tokens: TokenTotals
      active: boolean
      tab: PaneTab
      listOffset: number
    }
  }
}
