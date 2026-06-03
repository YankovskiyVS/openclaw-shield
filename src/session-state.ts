/**
 * Per-session flags set by L6 prompt scan until agent_end.
 */

export type UnsafeSessionRecord = {
  reason: string;
  at: number;
};

const unsafeSessions = new Map<string, UnsafeSessionRecord>();

export function markSessionUnsafe(sessionKey: string, reason: string): void {
  unsafeSessions.set(sessionKey, { reason, at: Date.now() });
}

export function clearSessionUnsafe(sessionKey: string): void {
  unsafeSessions.delete(sessionKey);
}

export function isSessionUnsafe(sessionKey: string | undefined): UnsafeSessionRecord | undefined {
  if (!sessionKey) return undefined;
  return unsafeSessions.get(sessionKey);
}

export function clearAllSessionsForTests(): void {
  unsafeSessions.clear();
}
