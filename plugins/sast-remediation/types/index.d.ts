export type ProgressView =
  | { kind: 'none'; reason: string }
  | { kind: 'error'; message: string; checkedAt: number }
  | {
      kind: 'ok'
      total: number
      verified: number
      deferred: number
      byStatus: Record<string, number>
      checkers: { code: string; total: number; verified: number; remaining: number }[]
      checkedAt: number
    }

export type UsageView = {
  contextPercent?: number
  contextTokens?: number
  contextWindow?: number
  costUsd?: number
  rateLimits: { kind: string; percentUsed: number }[]
}

export type TokenTotals = { input: number; output: number; cacheRead: number; cacheWrite: number; requests: number }

declare module 'claude-code' {
  interface PluginState {
    'sast-remediation': { progress: ProgressView; usage: UsageView; tokens: TokenTotals; active: boolean }
  }
}
