/**
 * Shared plugin configuration types.
 */

export type GuardMode = "enforce" | "audit";

export type DirectoryAllowlistEntry = {
  pathPrefix: string;
  pathPrefixEnv?: string;
  allowedCommands: string[];
};

export type FoundationModelsScanResponseFormat = "hivetrace" | "json";

export type FoundationModelsScanConfig = {
  enabled?: boolean;
  baseUrlEnv?: string;
  apiKeyEnv?: string;
  modelEnv?: string;
  model?: string;
  timeoutMs?: number;
  onScanFailure?: "fallback" | "block";
  /** hivetrace: model returns only true/false; json: legacy JSON classifier prompt */
  responseFormat?: FoundationModelsScanResponseFormat;
  /** Static X-App-Title header value (overridden by appTitleEnv when set) */
  appTitle?: string;
  appTitleEnv?: string;
};

export type GuardConfig = {
  mode?: GuardMode;
  layers?: {
    promptGuard?: boolean;
    outputScanner?: boolean;
    toolBlocker?: boolean;
    inputAudit?: boolean;
    securityGate?: boolean;
    promptScan?: boolean;
  };
  sensitiveFilePaths?: string[];
  destructiveCommands?: string[];
  disableDefaultDestructivePatterns?: boolean;
  directoryAllowlists?: DirectoryAllowlistEntry[];
  foundationModelsScan?: FoundationModelsScanConfig;
};

export const DEFAULT_FM_MODEL = "hivetrace/HiveTracePro";
export const DEFAULT_FM_TIMEOUT_MS = 15_000;
