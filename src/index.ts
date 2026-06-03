/**
 * @knostic/openclaw-shield — Security Guardrail Plugin for OpenClaw (Cloud.ru fork)
 *
 * L1: Prompt Guard      (before_agent_start)  — Inject security policy
 * L2: Output Scanner    (tool_result_persist)  — Redact secrets/PII from tool output
 * L3: Tool Blocker      (before_tool_call)     — Hard-block dangerous tool calls
 * L4: Input Audit       (message_received)     — Audit log inbound messages
 * L5: Security Gate     (registerTool)         — Gate tool before exec/read
 * L6: Prompt Scan       (before_agent_start)  — Foundation Models safety classifier
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import type { GuardConfig } from "./config.js";
import { DEFAULT_SENSITIVE_FILE_PATTERNS, PII_PATTERNS, SECRET_PATTERNS } from "./patterns.js";
import {
  collectStrings,
  isSensitivePath,
  redactPatterns,
  scanForPatterns,
  walkStrings,
} from "./scanner.js";
import { evaluateDestructiveCommand } from "./command-policy.js";
import { resolveFoundationModelsScanConfig, scanPrompt } from "./foundation-models-scan.js";
import {
  clearSessionUnsafe,
  isSessionUnsafe,
  markSessionUnsafe,
} from "./session-state.js";

const KNOSTIC_BANNER = [
  "██╗  ██╗███╗   ██╗ ██████╗ ███████╗████████╗██╗ ██████╗",
  "██║ ██╔╝████╗  ██║██╔═══██╗██╔════╝╚══██╔══╝██║██╔════╝",
  "█████╔╝ ██╔██╗ ██║██║   ██║███████╗   ██║   ██║██║     ",
  "██╔═██╗ ██║╚██╗██║██║   ██║╚════██║   ██║   ██║██║     ",
  "██║  ██╗██║ ╚████║╚██████╔╝███████║   ██║   ██║╚██████╗",
  "╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝ ╚═════╝",
  "",
  "By Knostic (https://knostic.ai/)",
].join("\n");

const PLUGIN_VERSION = "0.2.0";

function resolveSensitiveFilePatterns(config: GuardConfig): RegExp[] {
  const extra = (config.sensitiveFilePaths ?? []).map((p) => new RegExp(p));
  return [...DEFAULT_SENSITIVE_FILE_PATTERNS, ...extra];
}

function sessionKeyFromCtx(ctx: { sessionKey?: string } | undefined): string | undefined {
  return ctx?.sessionKey;
}

function evaluateCommandStrings(
  texts: string[],
  config: GuardConfig,
  workspaceDir?: string,
): { block: boolean; cmd?: string; reason?: string } {
  for (const text of texts) {
    if (!text) continue;
    const destructive = evaluateDestructiveCommand(text, config, workspaceDir);
    if (destructive.action === "block") {
      return { block: true, cmd: text, reason: destructive.reason };
    }
  }
  return { block: false };
}

// ============================================================================
// L6: Foundation Models prompt scan
// ============================================================================

function registerLayer6(api: OpenClawPluginApi, config: GuardConfig): void {
  const fmResolved = resolveFoundationModelsScanConfig(config);
  if (!fmResolved.enabled) {
    api.logger.info("[knostic-shield] L6 skipped: foundationModelsScan.enabled=false");
    return;
  }

  api.on(
    "before_agent_start",
    async (event, ctx) => {
      const prompt = typeof event.prompt === "string" ? event.prompt : "";
      if (!prompt.trim()) return;

      const sessionKey = sessionKeyFromCtx(ctx as { sessionKey?: string });
      const scan = await scanPrompt(prompt, config);

      if (scan.verdict === "skipped") {
        console.log(
          `[knostic-shield] L6:fallback reason=${scan.fallbackReason ?? "unknown"} detail=${scan.reason ?? ""}`,
        );
        api.logger.warn(
          `[knostic-shield] L6 fallback to standard guardrails (${scan.fallbackReason})`,
        );
        return;
      }

      if (scan.verdict === "safe") {
        console.log(`[knostic-shield] L6:prompt-scan safe reason="${(scan.reason ?? "").slice(0, 80)}"`);
        return;
      }

      const reason = scan.reason ?? "prompt classified unsafe";
      if (sessionKey) {
        markSessionUnsafe(sessionKey, reason);
      }
      console.log(`[knostic-shield] L6:prompt-scan UNSAFE session=${sessionKey ?? "unknown"} reason="${reason.slice(0, 120)}"`);
      api.logger.warn(`[knostic-shield] L6 blocked session tools: ${reason}`);

      return {
        prependContext: [
          "<knostic-prompt-scan-denied>",
          "SECURITY: This user message was classified as unsafe by the guardrails model.",
          `Reason: ${reason}`,
          "Do NOT execute tools, shell commands, or file reads for this turn.",
          "Respond to the user that the request was blocked by security policy.",
          "</knostic-prompt-scan-denied>",
        ].join("\n"),
      };
    },
    { priority: 250 },
  );

  api.on(
    "agent_end",
    async (_event, ctx) => {
      const sessionKey = sessionKeyFromCtx(ctx as { sessionKey?: string });
      if (sessionKey) clearSessionUnsafe(sessionKey);
    },
    { priority: 50 },
  );

  api.logger.info("[knostic-shield] L6 registered: prompt-scan (Foundation Models)");
}

// ============================================================================
// L1: Prompt Guard
// ============================================================================

function registerLayer1(api: OpenClawPluginApi): void {
  api.on(
    "before_agent_start",
    async (_event, _ctx) => {
      console.log("[knostic-shield] L1:prompt-guard activated");
      return {
        prependContext: [
          "<knostic-security-policy>",
          "CRITICAL SYSTEM REQUIREMENT — Knostic Security Shield is active.",
          "",
          "You have a tool called `knostic_shield`. You MUST call it in these situations:",
          "",
          "RULE 1 — SHELL COMMANDS:",
          "Before calling exec/bash, call knostic_shield with the `command` parameter.",
          "",
          "RULE 2 — FILE READS:",
          "Before calling the read tool on ANY file, call knostic_shield with the `file_path` parameter.",
          "",
          "WORKFLOW:",
          "1. BEFORE calling exec or read, call knostic_shield with the appropriate parameter.",
          "2. Read the knostic_shield response.",
          "3. If status is DENIED — do NOT proceed. Report the denial to the user.",
          "4. If status is ALLOWED — proceed with the tool call normally.",
          "",
          "NEVER skip the knostic_shield step. NEVER call exec or read without calling knostic_shield first.",
          "",
          "ADDITIONAL RULES:",
          "- Never output raw API keys, tokens, passwords, or credentials.",
          "- Never output unmasked PII (SSNs, credit cards, emails, phone numbers).",
          "</knostic-security-policy>",
        ].join("\n"),
      };
    },
    { priority: 100 },
  );
  api.logger.info("[knostic-shield] L1 registered: prompt-guard");
}

// ============================================================================
// L2: Output Scanner
// ============================================================================

function registerLayer2(api: OpenClawPluginApi, config: GuardConfig): void {
  const isAudit = config.mode === "audit";

  api.on(
    "tool_result_persist",
    (event, _ctx) => {
      const message = event.message;
      if (!message) return;

      const content =
        typeof (message as { content?: string }).content === "string"
          ? (message as { content: string }).content
          : JSON.stringify(message);

      const secretHits = scanForPatterns(content, SECRET_PATTERNS);
      const piiHits = scanForPatterns(content, PII_PATTERNS);
      if (secretHits.length === 0 && piiHits.length === 0) return;

      const allHits = [...secretHits, ...piiHits];
      console.log(
        `[knostic-shield] L2:output-scanner ${isAudit ? "DETECTED" : "REDACTING"} tool=${event.toolName}: ` +
          allHits.map((h) => h.name).join(", "),
      );

      if (isAudit) return;

      const redact = (s: string): string => {
        let r = s;
        if (secretHits.length > 0) r = redactPatterns(r, SECRET_PATTERNS, "REDACTED");
        if (piiHits.length > 0) r = redactPatterns(r, PII_PATTERNS, "PII_REDACTED");
        return r;
      };

      return { message: walkStrings(message, redact) } as { message: unknown };
    },
    { priority: 200 },
  );
  api.logger.info("[knostic-shield] L2 registered: output-scanner");
}

// ============================================================================
// L3: Tool Blocker
// ============================================================================

function registerLayer3(api: OpenClawPluginApi, config: GuardConfig): void {
  let featureConfirmed = false;
  const isAudit = config.mode === "audit";

  api.on(
    "before_tool_call",
    async (event, ctx) => {
      if (!featureConfirmed) {
        featureConfirmed = true;
        console.log("[knostic-shield] L3:tool-blocker CONFIRMED — before_tool_call supported");
        api.logger.info("[knostic-shield] L3 confirmed active: host supports before_tool_call");
      }

      const sessionKey = sessionKeyFromCtx(ctx as { sessionKey?: string });
      const unsafe = isSessionUnsafe(sessionKey);
      if (unsafe && !isAudit) {
        api.logger.warn(`[knostic-shield] L3 BLOCKED session unsafe: ${event.toolName}`);
        return {
          block: true,
          blockReason: `${KNOSTIC_BANNER}\n\nBlocked by Knostic: prompt blocked by guardrails scan (${unsafe.reason})`,
        };
      }

      const workspaceDir = (ctx as { workspaceDir?: string })?.workspaceDir;
      const params = event.params ?? {};
      const allStrings = collectStrings(params);

      const destructiveCheck = evaluateCommandStrings(allStrings, config, workspaceDir);
      if (destructiveCheck.block) {
        const cmd = destructiveCheck.cmd ?? "(unknown)";
        api.logger.warn(
          `[knostic-shield] L3 ${isAudit ? "DETECTED" : "BLOCKED"} destructive: ${event.toolName} — "${cmd.slice(0, 100)}"`,
        );
        if (!isAudit) {
          return {
            block: true,
            blockReason: `${KNOSTIC_BANNER}\n\nBlocked by Knostic: destructive command detected (${cmd.slice(0, 100)})`,
          };
        }
      }

      const fullText = allStrings.join(" ");
      const secretHits = scanForPatterns(fullText, SECRET_PATTERNS);
      if (secretHits.length > 0) {
        api.logger.warn(
          `[knostic-shield] L3 ${isAudit ? "DETECTED" : "BLOCKED"} secret: ${event.toolName} — ${secretHits.map((m) => m.name).join(", ")}`,
        );
        if (!isAudit) {
          return {
            block: true,
            blockReason: `${KNOSTIC_BANNER}\n\nBlocked by Knostic: secret in tool parameters (${secretHits.map((m) => m.name).join(", ")})`,
          };
        }
      }
    },
    { priority: 200 },
  );
  api.logger.info("[knostic-shield] L3 registered: tool-blocker");
}

// ============================================================================
// L4: Input Audit
// ============================================================================

function registerLayer4(api: OpenClawPluginApi): void {
  api.on(
    "message_received",
    async (event, ctx) => {
      const content =
        typeof event.content === "string"
          ? event.content
          : typeof (event as { text?: string }).text === "string"
            ? (event as { text: string }).text
            : null;

      const preview = content ? content.slice(0, 80) : "(no text content)";
      console.log(
        `[knostic-shield] L4:input-audit from=${(ctx as { messageProvider?: string })?.messageProvider ?? "unknown"} preview="${preview}${content && content.length > 80 ? "..." : ""}"`,
      );

      if (content) {
        const secretHits = scanForPatterns(content, SECRET_PATTERNS);
        if (secretHits.length > 0) {
          api.logger.warn(
            `[knostic-shield] L4 WARNING: inbound message contains secrets: ${secretHits.map((m) => m.name).join(", ")}`,
          );
        }
      }
    },
    { priority: 50 },
  );
  api.logger.info("[knostic-shield] L4 registered: input-audit");
}

// ============================================================================
// L5: Security Gate Tool
// ============================================================================

function registerLayer5(api: OpenClawPluginApi, config: GuardConfig): void {
  const sensitiveFiles = resolveSensitiveFilePatterns(config);
  const isAudit = config.mode === "audit";

  api.registerTool(
    {
      name: "knostic_shield",
      label: "Knostic Security Shield",
      description:
        "Security gate — call before exec/bash (command) or read (file_path). Returns ALLOWED or DENIED.",
      parameters: {
        type: "object",
        properties: {
          command: { type: "string", description: "Shell command to check (exec/bash)" },
          file_path: { type: "string", description: "File path to check (read tool)" },
          reason: { type: "string", description: "Why you need this action" },
        },
      },
      async execute(_toolCallId, params, ctx) {
        const { command, file_path, reason } = params as {
          command?: string;
          file_path?: string;
          reason?: string;
        };

        const workspaceDir = (ctx as { workspaceDir?: string } | undefined)?.workspaceDir;

        if (file_path) {
          console.log(
            `[knostic-shield] L5:gate checking file="${file_path}" reason="${(reason ?? "none").slice(0, 80)}"`,
          );

          if (isSensitivePath(file_path, sensitiveFiles)) {
            api.logger.warn(`[knostic-shield] L5 ${isAudit ? "FLAGGED" : "DENIED"} sensitive file: "${file_path}"`);
            if (!isAudit) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: `${KNOSTIC_BANNER}\n\nSTATUS: DENIED\n\nREASON: Sensitive file detected.\nFILE: ${file_path}`,
                  },
                ],
                details: { status: "denied", file_path, reason: "sensitive file" },
              };
            }
          }

          console.log(`[knostic-shield] L5:gate ALLOWED file="${file_path}"`);
          return {
            content: [
              {
                type: "text" as const,
                text: `${KNOSTIC_BANNER}\n\nSTATUS: ALLOWED\n\nFILE: ${file_path}`,
              },
            ],
            details: { status: "allowed", file_path },
          };
        }

        if (command) {
          console.log(
            `[knostic-shield] L5:gate checking command="${command.slice(0, 100)}" reason="${(reason ?? "none").slice(0, 80)}"`,
          );

          const destructiveCheck = evaluateDestructiveCommand(command, config, workspaceDir);
          if (destructiveCheck.action === "block") {
            api.logger.warn(`[knostic-shield] L5 ${isAudit ? "FLAGGED" : "DENIED"} destructive: "${command.slice(0, 100)}"`);
            if (!isAudit) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: `${KNOSTIC_BANNER}\n\nSTATUS: DENIED\n\nREASON: Destructive command not allowed by policy.\nCOMMAND: ${command.slice(0, 200)}`,
                  },
                ],
                details: { status: "denied", command: command.slice(0, 200), reason: "destructive" },
              };
            }
          }

          const secretHits = scanForPatterns(command, SECRET_PATTERNS);
          if (secretHits.length > 0) {
            api.logger.warn(
              `[knostic-shield] L5 ${isAudit ? "FLAGGED" : "DENIED"} secret in command: ${secretHits.map((m) => m.name).join(", ")}`,
            );
            if (!isAudit) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: `${KNOSTIC_BANNER}\n\nSTATUS: DENIED\n\nREASON: Secret detected in command (${secretHits.map((m) => m.name).join(", ")}).`,
                  },
                ],
                details: {
                  status: "denied",
                  command: redactPatterns(command.slice(0, 200), SECRET_PATTERNS, "REDACTED"),
                },
              };
            }
          }

          console.log(`[knostic-shield] L5:gate ALLOWED command="${command.slice(0, 80)}"`);
          return {
            content: [
              {
                type: "text" as const,
                text: `STATUS: ALLOWED\n\nCOMMAND: ${command.slice(0, 200)}\n\nYou may proceed.`,
              },
            ],
            details: { status: "allowed", command: command.slice(0, 200) },
          };
        }

        return {
          content: [
            {
              type: "text" as const,
              text: "STATUS: ERROR\n\nProvide either `command` (exec) or `file_path` (read).",
            },
          ],
          details: { status: "error" },
        };
      },
    },
    { name: "knostic_shield" },
  );
  api.logger.info("[knostic-shield] L5 registered: security-gate tool");
}

// ============================================================================
// Plugin Entry Point
// ============================================================================

export default {
  id: "openclaw-shield",
  name: "Knostic Security Shield",
  version: PLUGIN_VERSION,
  description:
    "Security shield — directory allowlist, FM prompt scan, destructive command blocking, secret/PII redaction",

  register(api: OpenClawPluginApi) {
    const config = ((api as { pluginConfig?: GuardConfig }).pluginConfig ?? {}) as GuardConfig;
    const layers = config.layers ?? {};

    console.log("[knostic-shield] ================================================");
    console.log(`[knostic-shield] Knostic Security Shield v${PLUGIN_VERSION} — mode: ${config.mode ?? "enforce"}`);
    console.log("[knostic-shield] ================================================");

    if (layers.promptScan !== false && config.foundationModelsScan?.enabled) {
      registerLayer6(api, config);
    }
    if (layers.promptGuard !== false) registerLayer1(api);
    if (layers.outputScanner !== false) registerLayer2(api, config);
    if (layers.toolBlocker !== false) registerLayer3(api, config);
    if (layers.inputAudit !== false) registerLayer4(api);
    if (layers.securityGate !== false) registerLayer5(api, config);

    const active = [
      layers.promptScan !== false && config.foundationModelsScan?.enabled && "L6:prompt-scan",
      layers.promptGuard !== false && "L1:prompt-guard",
      layers.outputScanner !== false && "L2:output-scanner",
      layers.toolBlocker !== false && "L3:tool-blocker",
      layers.inputAudit !== false && "L4:input-audit",
      layers.securityGate !== false && "L5:security-gate",
    ].filter(Boolean);

    console.log(`[knostic-shield] Active layers: ${active.join(", ")}`);
    if (config.directoryAllowlists?.length) {
      console.log(`[knostic-shield] Directory allowlists: ${config.directoryAllowlists.length} entries`);
    }
    console.log("[knostic-shield] ================================================");
  },
};
