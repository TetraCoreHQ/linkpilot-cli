/**
 * Getting a secret into the process without leaking it on the way in.
 *
 * THIS IS THE POINT OF THE FILE. `linkpilot secret "hunter2"` puts the secret
 * into the shell's history file and into the process list, where any other
 * user on the machine can read it with `ps`. The whole product exists to stop
 * a secret being readable by people who should not read it, so a CLI that
 * leaks it before encryption would be self-defeating.
 *
 * So: stdin is the primary path, an interactive prompt is the fallback, and
 * passing the secret as an argument still works but warns, because refusing
 * outright would just push people to a worse workaround.
 */

import { createInterface } from "node:readline";

export type SecretSource = "stdin" | "prompt" | "argument" | "file";

export interface SecretInput {
  value: string;
  source: SecretSource;
  /** Shown to the user. Non-empty only when the input route leaked something. */
  warning?: string;
}

/** True when stdin is a pipe or a file rather than a terminal. */
export function stdinIsPiped(stream: NodeJS.ReadStream = process.stdin): boolean {
  return !stream.isTTY;
}

export async function readAllStdin(stream: NodeJS.ReadStream = process.stdin): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Prompt without echoing. Node has no built-in hidden prompt, so the terminal
 * is put into raw mode and characters are consumed manually.
 */
export async function promptHidden(
  question: string,
  input: NodeJS.ReadStream = process.stdin,
  output: NodeJS.WriteStream = process.stderr,
): Promise<string> {
  if (!input.isTTY) throw new Error("Cannot prompt: stdin is not a terminal.");
  output.write(question);
  const rl = createInterface({ input, output, terminal: true });
  // Swallow echo while the answer is typed.
  const muted = output.write.bind(output);
  (rl as unknown as { _writeToOutput: (s: string) => void })._writeToOutput = () => {};
  try {
    const answer = await new Promise<string>((resolve) => rl.question("", resolve));
    muted("\n");
    return answer;
  } finally {
    rl.close();
  }
}

/**
 * Resolve the secret from, in order: stdin (if piped), the argument, or an
 * interactive hidden prompt.
 *
 * A trailing newline from `echo` is stripped, because `echo hunter2 |` is the
 * obvious thing to type and a stray "\n" in someone's password is a support
 * ticket nobody enjoys. Anything more than that is left alone: leading spaces
 * and internal newlines can be meaningful in a key or a certificate.
 */
export async function resolveSecret(args: {
  argument?: string;
  stdin?: NodeJS.ReadStream;
  interactive?: boolean;
}): Promise<SecretInput> {
  const stream = args.stdin ?? process.stdin;

  if (stdinIsPiped(stream)) {
    const raw = await readAllStdin(stream);
    const value = raw.replace(/\r?\n$/, "");
    if (value !== "") return { value, source: "stdin" };
    // EMPTY stdin is not an error on its own. A script, cron job or CI run
    // gets stdin pointed at /dev/null or a closed pipe, which is "not a TTY"
    // but carries nothing. Falling through to the argument keeps the
    // documented `linkpilot secret "text"` form working outside an
    // interactive terminal; only the case with no input at all fails.
    if (args.argument === undefined || args.argument === "") {
      throw new Error("Nothing on stdin. Pipe the secret in, or pass it as an argument.");
    }
  }

  if (args.argument !== undefined && args.argument !== "") {
    return {
      value: args.argument,
      source: "argument",
      warning:
        "The secret was passed as a command-line argument, so it is now in your shell history and was visible in the process list. Prefer: echo 'secret' | linkpilot secret --stdin",
    };
  }

  if (args.interactive === false) {
    throw new Error("No secret given. Pipe it on stdin or pass it as an argument.");
  }

  const typed = await promptHidden("Secret (input hidden): ");
  if (typed === "") throw new Error("No secret entered.");
  return { value: typed, source: "prompt" };
}
