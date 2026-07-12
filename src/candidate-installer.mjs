import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";

export const CANDIDATE_NAME = "project-tiny-context-harness";

export async function installCandidate(root, tarball, expectedSha256) {
  const candidate = await realpath(tarball);
  const actual = await sha256File(candidate);
  if (actual !== expectedSha256) throw new Error(`candidate_sha256_mismatch:${actual}`);
  await mkdir(root, { recursive: true });
  await writeFile(path.join(root, "package.json"), `${JSON.stringify({ name: "external-audit-candidate-install", private: true, version: "1.0.0" }, null, 2)}\n`);
  const installed = await runProcess("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=false", candidate], { cwd: root, timeoutMs: 10 * 60_000 });
  if (installed.status !== 0) throw new Error(`candidate_install_failed:${safeCode(`${installed.stdout}\n${installed.stderr}`)}`);
  const packageRoot = path.join(root, "node_modules", CANDIDATE_NAME);
  const manifest = JSON.parse(await readFile(path.join(packageRoot, "package.json"), "utf8"));
  if (manifest.name !== CANDIDATE_NAME || manifest.bin?.["ty-context"] !== "dist/cli.js") throw new Error("candidate_package_identity_invalid");
  return { packageRoot, cliPath: path.join(packageRoot, "dist", "cli.js"), version: manifest.version, sha256: actual };
}

export async function sha256File(file) {
  return createHash("sha256").update(await readFile(file)).digest("hex");
}

export function canonical(value) {
  return JSON.stringify(sort(value));
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function safeCode(value) {
  const text = String(value ?? "");
  const candidates = text.match(/\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/gu) ?? [];
  return candidates[0] ?? "external_audit_failure";
}

export function runProcess(file, argv, { cwd, env = process.env, input = "", timeoutMs = 180_000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(file, argv, { cwd, env, shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
    const stdout = []; const stderr = []; let settled = false;
    const finish = (error, result) => { if (settled) return; settled = true; clearTimeout(timer); error ? reject(error) : resolve(result); };
    child.stdout.on("data", (chunk) => stdout.push(Buffer.from(chunk)));
    child.stderr.on("data", (chunk) => stderr.push(Buffer.from(chunk)));
    child.once("error", (error) => finish(error));
    child.once("exit", (code, signal) => finish(undefined, { status: code ?? -1, signal, stdout: Buffer.concat(stdout).toString("utf8").trim(), stderr: Buffer.concat(stderr).toString("utf8").trim() }));
    const timer = setTimeout(() => { child.kill(); finish(new Error(`external_audit_timeout:${path.basename(file)}`)); }, timeoutMs); timer.unref();
    child.stdin.end(input);
  });
}

function sort(value) {
  if (Array.isArray(value)) return value.map(sort);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sort(value[key])]));
  return value;
}
