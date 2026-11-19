// Thin launcher: the Go binary (./forge) owns the suite lifecycle. This
// file only spawns it (inheriting the environment), forwards SIGTERM/SIGINT
// to it, and exits with its exit code.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const dir = dirname(fileURLToPath(import.meta.url));
const forge = join(dir, "forge");

const child = spawn(forge, [], { stdio: "inherit", env: process.env });

const forward = (signal: NodeJS.Signals): void => {
  child.kill(signal);
};
process.on("SIGTERM", () => forward("SIGTERM"));
process.on("SIGINT", () => forward("SIGINT"));

child.on("exit", (code) => {
  process.exit(code ?? 1);
});
