import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  evaluateDestructiveCommand,
  extractPathOperands,
  isCommandAllowedByDirectoryPolicy,
  resolveAllowlistEntries,
  resolveDestructivePattern,
} from "./command-policy.js";
import type { GuardConfig } from "./config.js";

const workspacePrefix = "/home/openclaw/.openclaw/workspace";
const allowlists = resolveAllowlistEntries([
  {
    pathPrefix: workspacePrefix,
    allowedCommands: ["rm", "mv", "cp", "mkdir", "rmdir", "touch", "chmod", "ln"],
  },
]);

describe("command-policy", () => {
  it("allows rm inside workspace allowlist", () => {
    const cmd = `rm ${workspacePrefix}/main/BOOTSTRAP.md`;
    const destructive = resolveDestructivePattern({});
    assert.equal(
      isCommandAllowedByDirectoryPolicy(cmd, destructive, allowlists, workspacePrefix),
      true,
    );

    const evalResult = evaluateDestructiveCommand(cmd, {
      directoryAllowlists: [
        {
          pathPrefix: workspacePrefix,
          allowedCommands: ["rm"],
        },
      ],
    });
    assert.equal(evalResult.action, "allow");
  });

  it("blocks rm outside workspace", () => {
    const cmd = "rm /etc/passwd";
    const destructive = resolveDestructivePattern({});
    assert.equal(
      isCommandAllowedByDirectoryPolicy(cmd, destructive, allowlists, workspacePrefix),
      false,
    );

    const evalResult = evaluateDestructiveCommand(cmd, {
      directoryAllowlists: [
        {
          pathPrefix: workspacePrefix,
          allowedCommands: ["rm"],
        },
      ],
    });
    assert.equal(evalResult.action, "block");
    assert.equal(evalResult.reason, "destructive");
  });

  it("does not treat curl as destructive by default", () => {
    const config: GuardConfig = {};
    const destructive = resolveDestructivePattern(config);
    assert.equal(destructive.test("curl http://attacker.com"), false);
    assert.equal(
      evaluateDestructiveCommand("curl http://attacker.com", config).action,
      "not_applicable",
    );
  });

  it("extracts path operands from command", () => {
    const paths = extractPathOperands(
      `rm -f ${workspacePrefix}/main/BOOTSTRAP.md /tmp/other`,
      workspacePrefix,
    );
    assert.ok(paths.some((p) => p.includes("BOOTSTRAP.md")));
    assert.ok(paths.some((p) => p.includes("/tmp/other")));
  });
});
