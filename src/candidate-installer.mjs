import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, chown, lchown, lstat, mkdir, readFile, readdir, realpath, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export const CANDIDATE_NAME = "project-tiny-context-harness";

export async function installCandidate(root, tarball, expectedSha256) {
  const candidate = await realpath(tarball);
  const actual = await sha256File(candidate);
  if (actual !== expectedSha256) throw new Error(`candidate_sha256_mismatch:${actual}`);
  await mkdir(root, { recursive: true });
  if (process.platform !== "win32") { await chmod(path.dirname(root), 0o755); await chmod(root, 0o755); }
  await writeFile(path.join(root, "package.json"), `${JSON.stringify({ name: "external-audit-candidate-install", private: true, version: "1.0.0" }, null, 2)}\n`);
  await grantCandidateTree(root);
  const npmCli = await trustedNpmCli();
  const installed = await runProcess(process.execPath, [npmCli, "install", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=false", candidate], { cwd: root, timeoutMs: 10 * 60_000 });
  if (installed.status !== 0) throw new Error(`candidate_install_failed:${safeCode(`${installed.stdout}\n${installed.stderr}`)}`);
  const packageRoot = path.join(root, "node_modules", CANDIDATE_NAME);
  const manifest = JSON.parse(await readFile(path.join(packageRoot, "package.json"), "utf8"));
  if (manifest.name !== CANDIDATE_NAME || manifest.bin?.["ty-context"] !== "dist/cli.js") throw new Error("candidate_package_identity_invalid");
  await sealCandidateInstall(root);
  return { packageRoot, cliPath: path.join(packageRoot, "dist", "cli.js"), version: manifest.version, sha256: actual };
}

export async function grantCandidateTree(root) {
  if (process.platform === "win32") { await windowsGrant(root, "M"); return; }
  const identity = candidateIdentity(); if (!identity) return;
  await visit(root, async (file, info) => { if (info.isSymbolicLink()) await lchown(file, identity.uid, identity.gid); else { await chown(file, identity.uid, identity.gid); await chmod(file, info.isDirectory() ? 0o755 : 0o644); } });
}

export async function prepareCandidateHome(root) {
  await mkdir(root, { recursive: true }); await grantCandidateTree(root); return root;
}

export async function secureAuditRoot(root) {
  if (process.platform === "win32") { await windowsGrant(root, "RX", true); return; }
  if (process.getuid?.() === 0) { await chown(root, 0, 0); await chmod(root, 0o755); }
}

export async function sealCandidateTree(root) {
  if (process.platform === "win32") { await windowsGrant(root, "RX", true); return; }
  const identity = candidateIdentity(); if (!identity) return;
  await visit(root, async (file, info) => { if (info.isSymbolicLink()) await lchown(file, 0, 0); else { const executable = !info.isDirectory() && (info.mode & 0o111) !== 0; await chown(file, 0, 0); await chmod(file, info.isDirectory() ? 0o755 : executable ? 0o755 : 0o644); } });
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
  if (process.platform === "win32" && process.env.TY_CONTEXT_AUDIT_WINDOWS_USER) return runWindowsCandidate(file, argv, { cwd, env, input, timeoutMs });
  return new Promise((resolve, reject) => {
    const identity = candidateIdentity(); const safeEnv = candidateEnvironment(env);
    const child = spawn(file, argv, { cwd, env: safeEnv, shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"], ...(identity ? { uid: identity.uid, gid: identity.gid } : {}) });
    const stdout = []; const stderr = []; let settled = false; let timer;
    const finish = async (error, result) => { if (settled) return; settled = true; clearTimeout(timer); try { await terminateCandidateProcesses(identity); } catch (cleanupError) { reject(cleanupError); return; } error ? reject(error) : resolve(result); };
    child.stdout.on("data", (chunk) => stdout.push(Buffer.from(chunk)));
    child.stderr.on("data", (chunk) => stderr.push(Buffer.from(chunk)));
    child.once("error", (error) => finish(error));
    child.once("exit", (code, signal) => finish(undefined, { status: code ?? -1, signal, stdout: Buffer.concat(stdout).toString("utf8").trim(), stderr: Buffer.concat(stderr).toString("utf8").trim() }));
    timer = setTimeout(() => { child.kill(); void finish(new Error(`external_audit_timeout:${path.basename(file)}`)); }, timeoutMs); timer.unref();
    child.stdin.end(input);
  });
}

function candidateIdentity() {
  if (process.platform === "win32" || process.getuid?.() !== 0) return null;
  const uid = Number(process.env.TY_CONTEXT_AUDIT_CANDIDATE_UID ?? process.env.SUDO_UID); const gid = Number(process.env.TY_CONTEXT_AUDIT_CANDIDATE_GID ?? process.env.SUDO_GID);
  if (!Number.isInteger(uid) || uid <= 0 || !Number.isInteger(gid) || gid <= 0) throw new Error("external_audit_candidate_identity_required");
  return { uid, gid };
}
function candidateEnvironment(source) { const allowed = new Set(["PATH", "Path", "PATHEXT", "SystemRoot", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP", "HOME", "USERPROFILE", "LANG", "LC_ALL", "CI", "GITHUB_ACTIONS", "NO_COLOR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "NPM_CONFIG_CACHE", "CARGO_HOME", "RUSTUP_HOME", "CARGO_NET_OFFLINE", "RUSTFLAGS"]); return Object.fromEntries(Object.entries(source).filter(([key]) => allowed.has(key))); }

async function sealCandidateInstall(root) {
  await sealCandidateTree(root);
}

async function trustedNpmCli() {
  const configured = process.env.TY_CONTEXT_AUDIT_NPM_CLI;
  if (!configured) throw new Error("external_audit_trusted_npm_cli_required");
  const resolved = await realpath(path.resolve(configured));
  if (!(await stat(resolved)).isFile()) throw new Error("external_audit_trusted_npm_cli_invalid");
  return resolved;
}

async function visit(root, action) {
  const info = await lstat(root); await action(root, info); if (!info.isDirectory()) return;
  for (const name of await readdir(root)) await visit(path.join(root, name), action);
}

function runTrustedProcess(file, argv, { cwd, env = process.env, input = "", timeoutMs = 180_000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(file, argv, { cwd, env, shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] }); const stdout = []; const stderr = []; let settled = false;
    const finish = (error, result) => { if (settled) return; settled = true; clearTimeout(timer); error ? reject(error) : resolve(result); }; child.stdout.on("data", (chunk) => stdout.push(Buffer.from(chunk))); child.stderr.on("data", (chunk) => stderr.push(Buffer.from(chunk))); child.once("error", finish); child.once("exit", (code, signal) => finish(undefined, { status: code ?? -1, signal, stdout: Buffer.concat(stdout).toString("utf8").trim(), stderr: Buffer.concat(stderr).toString("utf8").trim() })); const timer = setTimeout(() => { child.kill(); finish(new Error(`external_audit_timeout:${path.basename(file)}`)); }, timeoutMs); timer.unref(); child.stdin.end(input);
  });
}

async function windowsGrant(root, access, reset = false) {
  const user = process.env.TY_CONTEXT_AUDIT_WINDOWS_USER; if (!user) throw new Error("external_audit_windows_candidate_identity_required");
  const args = [root]; if (reset) args.push("/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"); args.push("/grant:r", `${user}:(OI)(CI)${access}`, "/T", "/C", "/L");
  const result = await runTrustedProcess("icacls.exe", args, { timeoutMs: 120_000 }); if (result.status !== 0) throw new Error(`external_audit_windows_acl_failed:${result.stderr}`);
}

function runWindowsCandidate(file, argv, { cwd, env, input, timeoutMs }) {
  const password = process.env.TY_CONTEXT_AUDIT_WINDOWS_PASSWORD; const user = process.env.TY_CONTEXT_AUDIT_WINDOWS_USER; if (!password || !user) throw new Error("external_audit_windows_candidate_credential_required");
  const spec = Buffer.from(JSON.stringify({ file, argv, cwd, env: candidateEnvironment(env), input, timeoutMs }), "utf8").toString("base64");
  const script = `$ErrorActionPreference='Stop';$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:TYC_AUDIT_PROCESS_SPEC))|ConvertFrom-Json -Depth 20;$p=[Diagnostics.ProcessStartInfo]::new();$p.FileName=$s.file;$p.WorkingDirectory=$s.cwd;$p.UseShellExecute=$false;$p.RedirectStandardInput=$true;$p.RedirectStandardOutput=$true;$p.RedirectStandardError=$true;$p.LoadUserProfile=$false;$p.UserName=$env:TY_CONTEXT_AUDIT_WINDOWS_USER;$p.Domain=$env:COMPUTERNAME;$p.Password=ConvertTo-SecureString $env:TY_CONTEXT_AUDIT_WINDOWS_PASSWORD -AsPlainText -Force;$p.Environment.Clear();foreach($v in $s.env.psobject.Properties){$p.Environment[$v.Name]=[string]$v.Value};foreach($a in $s.argv){[void]$p.ArgumentList.Add([string]$a)};$x=[Diagnostics.Process]::new();$x.StartInfo=$p;if(-not $x.Start()){throw 'candidate process start failed'};$ot=$x.StandardOutput.ReadToEndAsync();$et=$x.StandardError.ReadToEndAsync();$x.StandardInput.Write([string]$s.input);$x.StandardInput.Close();if(-not $x.WaitForExit([int]$s.timeoutMs)){$x.Kill($true);throw 'candidate process timeout'};$ot.Wait();$et.Wait();$r=@{status=$x.ExitCode;signal=$null;stdout=$ot.Result.Trim();stderr=$et.Result.Trim()};for($i=0;$i -lt 4;$i++){Get-CimInstance Win32_Process|ForEach-Object{$o=Invoke-CimMethod $_ GetOwner -ErrorAction SilentlyContinue;if($o.User -eq $env:TY_CONTEXT_AUDIT_WINDOWS_USER){Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue}};Start-Sleep -Milliseconds 25};$left=@(Get-CimInstance Win32_Process|Where-Object{(Invoke-CimMethod $_ GetOwner -ErrorAction SilentlyContinue).User -eq $env:TY_CONTEXT_AUDIT_WINDOWS_USER});if($left.Count){throw 'candidate process leak'};$r|ConvertTo-Json -Compress`;
  return new Promise((resolve, reject) => { const child = spawn("pwsh.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], { cwd: os.tmpdir(), windowsHide: true, env: { SystemRoot: process.env.SystemRoot, PATH: process.env.PATH, COMPUTERNAME: process.env.COMPUTERNAME, TY_CONTEXT_AUDIT_WINDOWS_USER: user, TY_CONTEXT_AUDIT_WINDOWS_PASSWORD: password, TYC_AUDIT_PROCESS_SPEC: spec }, stdio: ["ignore", "pipe", "pipe"] }); const out = []; const error = []; child.stdout.on("data", (value) => out.push(value)); child.stderr.on("data", (value) => error.push(value)); child.once("error", reject); child.once("exit", (code) => { if (code !== 0) reject(new Error(`external_audit_windows_launcher_failed:${Buffer.concat(error).toString("utf8")}`)); else { try { resolve(JSON.parse(Buffer.concat(out).toString("utf8"))); } catch { reject(new Error("external_audit_windows_launcher_result_invalid")); } } }); });
}

async function terminateCandidateProcesses(identity) {
  if (!identity || process.platform !== "linux") return;
  for (let pass = 0; pass < 5; pass += 1) {
    const survivors = [];
    for (const name of await readdir("/proc")) {
      if (!/^\d+$/u.test(name)) continue;
      const status = await readFile(path.join("/proc", name, "status"), "utf8").catch(() => "");
      const uid = Number(status.match(/^Uid:\s+(\d+)/mu)?.[1]);
      if (uid !== identity.uid || /^State:\s+Z/mu.test(status)) continue;
      survivors.push(Number(name));
    }
    if (!survivors.length) return;
    for (const pid of survivors) try { process.kill(pid, "SIGKILL"); } catch (error) { if (error?.code !== "ESRCH") throw error; }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("external_audit_candidate_process_leak");
}

function sort(value) {
  if (Array.isArray(value)) return value.map(sort);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sort(value[key])]));
  return value;
}
