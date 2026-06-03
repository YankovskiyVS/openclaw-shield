/**
 * Directory allowlist policy for destructive shell commands.
 */

import path from "node:path";
import { DEFAULT_DESTRUCTIVE_CMD } from "./patterns.js";
import type { DirectoryAllowlistEntry, GuardConfig } from "./config.js";

const DESTRUCTIVE_VERBS = new Set([
  "rm",
  "rmdir",
  "unlink",
  "del",
  "format",
  "mkfs",
]);

/** Path-like tokens in shell commands (absolute, relative, ~). */
const PATH_TOKEN =
  /(?:~\/[^\s;|&><"']+|\/[^\s;|&><"']+|\.\.?\/[^\s;|&><"']+|[A-Za-z0-9_.-]+\/[^\s;|&><"']+)/g;

export type CommandEvaluation = {
  action: "allow" | "block" | "not_applicable";
  reason?: "destructive" | "secret";
};

export function resolveDestructivePattern(config: GuardConfig): RegExp {
  if (config.disableDefaultDestructivePatterns) {
    const extra = config.destructiveCommands ?? [];
    if (extra.length === 0) {
      return /(?!)/;
    }
    return new RegExp(extra.map((p) => `(?:${p})`).join("|"));
  }

  const extra = config.destructiveCommands ?? [];
  if (extra.length === 0) return DEFAULT_DESTRUCTIVE_CMD;

  const combined = `${DEFAULT_DESTRUCTIVE_CMD.source}|${extra.map((p) => `(?:${p})`).join("|")}`;
  return new RegExp(combined);
}

export function resolveAllowlistEntries(
  entries: DirectoryAllowlistEntry[] | undefined,
): Array<{ pathPrefix: string; allowedCommands: Set<string> }> {
  if (!entries?.length) return [];

  return entries
    .map((entry) => {
      const prefix =
        (entry.pathPrefixEnv ? process.env[entry.pathPrefixEnv]?.trim() : undefined) ||
        entry.pathPrefix?.trim();
      if (!prefix) return null;

      const normalized = normalizePath(prefix);
      const allowed = new Set(
        (entry.allowedCommands ?? []).map((c) => c.toLowerCase().trim()).filter(Boolean),
      );
      return { pathPrefix: normalized, allowedCommands: allowed };
    })
    .filter((e): e is { pathPrefix: string; allowedCommands: Set<string> } => e !== null);
}

export function normalizePath(filePath: string, workspaceDir?: string): string {
  const trimmed = filePath.trim().replace(/^['"]|['"]$/g, "");
  if (!trimmed) return "";

  let resolved = trimmed.startsWith("~")
    ? path.join(workspaceDir ?? process.env.HOME ?? "/", trimmed.slice(1))
    : trimmed;

  if (!path.isAbsolute(resolved) && workspaceDir) {
    resolved = path.join(workspaceDir, resolved);
  }

  return path.normalize(resolved);
}

export function extractCommandVerb(command: string): string | null {
  const trimmed = command.trim();
  if (!trimmed) return null;

  const first = trimmed.split(/\s+/)[0]?.toLowerCase() ?? "";
  if (first === "dd" && /\bdd\s+if=/i.test(trimmed)) return "dd";
  if (DESTRUCTIVE_VERBS.has(first)) return first;
  if (DEFAULT_DESTRUCTIVE_CMD.test(trimmed)) {
    const match = trimmed.match(DEFAULT_DESTRUCTIVE_CMD);
    return match?.[1]?.toLowerCase() ?? null;
  }
  return null;
}

export function extractPathOperands(command: string, workspaceDir?: string): string[] {
  const paths = new Set<string>();
  const matches = command.match(PATH_TOKEN) ?? [];
  for (const raw of matches) {
    const normalized = normalizePath(raw, workspaceDir);
    if (normalized && !normalized.startsWith("-")) {
      paths.add(normalized);
    }
  }
  return [...paths];
}

export function isCommandAllowedByDirectoryPolicy(
  command: string,
  destructivePattern: RegExp,
  allowlists: Array<{ pathPrefix: string; allowedCommands: Set<string> }>,
  workspaceDir?: string,
): boolean {
  if (!destructivePattern.test(command)) return false;
  if (allowlists.length === 0) return false;

  const verb = extractCommandVerb(command);
  if (!verb) return false;

  const operands = extractPathOperands(command, workspaceDir);
  if (operands.length === 0) return false;

  for (const operand of operands) {
    let matchedEntry: { pathPrefix: string; allowedCommands: Set<string> } | null = null;

    for (const entry of allowlists) {
      const prefix = entry.pathPrefix.endsWith(path.sep)
        ? entry.pathPrefix
        : entry.pathPrefix + path.sep;
      if (operand === entry.pathPrefix || operand.startsWith(prefix)) {
        matchedEntry = entry;
        break;
      }
    }

    if (!matchedEntry || !matchedEntry.allowedCommands.has(verb)) {
      return false;
    }
  }

  return true;
}

export function evaluateDestructiveCommand(
  command: string,
  config: GuardConfig,
  workspaceDir?: string,
): CommandEvaluation {
  const destructivePattern = resolveDestructivePattern(config);
  if (!destructivePattern.test(command)) {
    return { action: "not_applicable" };
  }

  const allowlists = resolveAllowlistEntries(config.directoryAllowlists);
  if (isCommandAllowedByDirectoryPolicy(command, destructivePattern, allowlists, workspaceDir)) {
    return { action: "allow" };
  }

  return { action: "block", reason: "destructive" };
}
