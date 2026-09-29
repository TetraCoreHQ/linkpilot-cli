/** Dispatch, kept separate from the bin shim so tests can drive it directly. */
import { parseArgs } from "./args.js";
import {
  HELP,
  cmdLinks,
  cmdLogin,
  cmdLogout,
  cmdRevoke,
  cmdSecret,
  cmdSecrets,
  cmdShorten,
  cmdWhoami,
  describeError,
  type Ctx,
} from "./commands.js";

/**
 * Kept in step with package.json by a test, not read from it at runtime.
 * Reading the manifest would tie `--version` to the file layout of the
 * installed tree and break the moment anyone bundles the CLI; a test fails
 * the release instead, which is the only moment the drift matters.
 */
export const VERSION = "0.1.3";

const COMMANDS: Record<string, (ctx: Ctx) => Promise<number>> = {
  secret: cmdSecret,
  shorten: cmdShorten,
  links: cmdLinks,
  secrets: cmdSecrets,
  revoke: cmdRevoke,
  whoami: cmdWhoami,
  login: cmdLogin,
  logout: cmdLogout,
};

export async function run(
  argv: string[],
  deps: Omit<Ctx, "argv"> & { argv?: never },
): Promise<number> {
  const parsed = parseArgs(argv);
  const ctx: Ctx = { ...deps, argv: parsed };

  if (parsed.flags.version) {
    ctx.out(VERSION);
    return 0;
  }
  if (parsed.flags.help || parsed.command === null || parsed.command === "help") {
    ctx.out(HELP);
    return parsed.command === null && !parsed.flags.help ? 1 : 0;
  }

  const fn = COMMANDS[parsed.command];
  if (!fn) {
    ctx.err(`Unknown command "${parsed.command}". Try: linkpilot --help`);
    return 1;
  }

  try {
    return await fn(ctx);
  } catch (e) {
    ctx.err(describeError(e));
    return 1;
  }
}
