/**
 * A very small argument parser.
 *
 * Deliberately hand-rolled rather than pulling in commander or yargs: the CLI
 * has six commands and a handful of flags, and a credential-handling tool is
 * a poor place to add dependency surface for the sake of convenience.
 */

export interface ParsedArgs {
  command: string | null;
  positional: string[];
  flags: Record<string, string | boolean>;
}

const KNOWN_BOOLEANS = new Set([
  "help",
  "version",
  "json",
  "stdin",
  "no-interactive",
  "anon",
  "quiet",
  "burn",
  "no-burn",
]);

export function parseArgs(argv: string[]): ParsedArgs {
  const flags: Record<string, string | boolean> = {};
  const positional: string[] = [];
  let sawTerminator = false;

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];

    // Everything after `--` is positional, so a secret starting with a dash
    // can still be passed.
    if (!sawTerminator && a === "--") {
      sawTerminator = true;
      continue;
    }
    if (sawTerminator || !a.startsWith("-")) {
      positional.push(a);
      continue;
    }

    const long = a.startsWith("--") ? a.slice(2) : a.slice(1);
    const eq = long.indexOf("=");
    if (eq >= 0) {
      flags[long.slice(0, eq)] = long.slice(eq + 1);
      continue;
    }
    if (KNOWN_BOOLEANS.has(long)) {
      flags[long] = true;
      continue;
    }
    // A value flag consumes the next token unless that token is itself a flag.
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith("-")) {
      flags[long] = next;
      i++;
    } else {
      flags[long] = true;
    }
  }

  return { command: positional.shift() ?? null, positional, flags };
}

export function flagString(flags: ParsedArgs["flags"], name: string): string | undefined {
  const v = flags[name];
  return typeof v === "string" ? v : undefined;
}

export function flagNumber(flags: ParsedArgs["flags"], name: string): number | undefined {
  const v = flagString(flags, name);
  if (v === undefined) return undefined;
  const n = Number(v);
  if (!Number.isInteger(n)) throw new Error(`--${name} must be a whole number of seconds.`);
  return n;
}

/**
 * Accepts `30m`, `2h`, `7d` and a bare number of seconds, because nobody
 * wants to work out that a week is 604800.
 */
export function parseTtl(raw: string | undefined): number | undefined {
  if (raw === undefined) return undefined;
  const m = /^(\d+)\s*([smhd]?)$/i.exec(raw.trim());
  if (!m) throw new Error("--ttl must look like 3600, 30m, 2h or 7d.");
  const n = Number(m[1]);
  const unit = (m[2] || "s").toLowerCase();
  const mult = unit === "s" ? 1 : unit === "m" ? 60 : unit === "h" ? 3600 : 86400;
  return n * mult;
}
