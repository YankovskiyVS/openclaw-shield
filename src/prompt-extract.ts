/**
 * Extract the latest user utterance for L6 scan (never send full transcript/history).
 */

const ROLE_LINE =
  /(?:^|\n)\s*(?:User|Human|user|human|Пользователь)\s*:\s*/g;

const NEXT_ROLE_LINE =
  /\n\s*(?:Assistant|AI|Bot|System|Ассистент|assistant|system)\s*:/i;

/**
 * Returns only the text of the current user turn for guardrails classification.
 */
export function extractLatestUserMessage(prompt: string): string {
  const trimmed = prompt.trim();
  if (!trimmed) return "";

  let lastStart = -1;
  let match: RegExpExecArray | null;
  const roleRe = new RegExp(ROLE_LINE.source, ROLE_LINE.flags);
  while ((match = roleRe.exec(trimmed)) !== null) {
    lastStart = match.index + match[0].length;
  }

  if (lastStart >= 0) {
    const slice = trimmed.slice(lastStart);
    const nextRole = slice.search(NEXT_ROLE_LINE);
    const segment = nextRole >= 0 ? slice.slice(0, nextRole) : slice;
    return segment.trim();
  }

  // Transcript blocks separated by blank lines — take the last non-empty block.
  const blocks = trimmed.split(/\n{2,}/).map((b) => b.trim()).filter(Boolean);
  if (blocks.length > 1) {
    return blocks[blocks.length - 1];
  }

  return trimmed;
}
