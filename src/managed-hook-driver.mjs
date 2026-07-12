import { spawn } from "node:child_process";
import { createPublicKey, verify } from "node:crypto";
import { chmod, cp, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";
import { canonical, runProcess, sha256 } from "./candidate-installer.mjs";

export async function acquireManagedHost(candidatePackageRoot, releaseRoot, options = {}) {
  const supplied = process.env.TY_CONTEXT_MANAGED_HOST_READY;
  if (supplied) { if (!options.allowReadyDescriptor) throw new Error("external_audit_ready_descriptor_forbidden_for_full_audit"); return { ready: JSON.parse(await readFile(supplied, "utf8")), close: async () => {} }; }
  if (process.platform === "win32") return startWindowsManagedHost(candidatePackageRoot, releaseRoot);
  if (process.platform !== "linux" || process.getuid?.() !== 0 || !await permittedLinuxRoot()) throw new Error("external_audit_managed_host_requires_linux_root_container_or_ready_descriptor");
  return startLinuxManagedHost(candidatePackageRoot, releaseRoot);
}

export async function invokeManagedHook(ready, repository, event, input = {}) {
  const payload = {
    hook_event_name: event,
    session_id: `external-audit-${process.pid}`,
    turn_id: `${event}-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    cwd: repository,
    source: input.source ?? "startup",
    stop_hook_active: input.stop_hook_active ?? false,
    last_assistant_message: input.last_assistant_message ?? null
  };
  const result = await runProcess(ready.codex_launcher, [ready.codex_script, process.execPath, ready.hook_path], { cwd: repository, input: JSON.stringify(payload), timeoutMs: 6 * 60 * 60_000 });
  if (result.status !== 0) throw new Error(`managed_hook_failed:${result.stderr}`);
  return JSON.parse(result.stdout || "{}");
}

async function startLinuxManagedHost(candidate, source) {
  const moduleAt = (relative) => import(pathToFileURL(path.join(candidate, ...relative.split("/"))).href);
  const [{ managedHostLayout }, { renderManagedRequirementsV1 }, release, { LONG_TASK_HOST_RELEASE_ROOT_PUBLIC_KEY_PEM }, runtimeIdentity, codec] = await Promise.all([
    moduleAt("dist/lib/long-task-managed-host-layout.js"),
    moduleAt("dist/lib/long-task-managed-requirements.js"),
    moduleAt("dist/lib/long-task-host-release.js"),
    moduleAt("dist/lib/long-task-host-release-root.js"),
    moduleAt("dist/lib/long-task-host-runtime-identity.js"),
    moduleAt("dist/lib/composite-campaign-codec.js")
  ]);
  const layout = managedHostLayout("linux");
  await release.verifyHostReleaseDirectoryV1(source, LONG_TASK_HOST_RELEASE_ROOT_PUBLIC_KEY_PEM, { platform: "linux", arch: process.arch });
  const root = await mkdtemp(path.join(os.tmpdir(), "tyc-external-audit-host-"));
  const readyPath = path.join(root, "managed-host-ready.json");
  const codexDirectory = "/usr/local/libexec";
  const codexLauncher = path.join(codexDirectory, "ty-context-external-audit-codex-launcher");
  const codexScript = path.join(codexDirectory, "ty-context-external-audit-codex-launcher.mjs");
  await Promise.all([rm(layout.managed_dir, { recursive: true, force: true }), rm(layout.state_root, { recursive: true, force: true }), rm(layout.requirements_file, { force: true }), rm(layout.endpoint, { force: true })]);
  await Promise.all([mkdir(layout.managed_dir, { recursive: true }), mkdir(layout.state_root, { recursive: true }), mkdir(path.dirname(layout.requirements_file), { recursive: true }), mkdir(path.dirname(layout.endpoint), { recursive: true }), mkdir(codexDirectory, { recursive: true })]);
  await Promise.all([
    cp(path.join(source, "ty-context-host-helper"), layout.helper_path), cp(path.join(source, "ty-context-host-admin"), layout.admin_path), cp(path.join(source, "ty-context-host-installer-ui"), layout.installer_ui_path),
    cp(path.join(source, "long-task-hook.mjs"), layout.hook_path), cp(path.join(source, "ty-context-host-worker.mjs"), layout.worker_path),
    cp(path.join(source, "requirements.toml"), path.join(layout.managed_dir, "requirements.toml")), cp(path.join(source, "host-release-manifest.json"), layout.release_manifest_path), cp(path.join(source, "host-release-manifest.sig"), layout.release_signature_path), cp(path.join(source, "host-release-root-public.pem"), layout.release_root_public_key_path), cp(process.execPath, codexLauncher)
  ]);
  await writeFile(codexScript, `import {spawnSync} from "node:child_process";const result=spawnSync(process.argv[2],process.argv.slice(3),{stdio:"inherit",windowsHide:true});process.exit(result.status??1);\n`);
  await Promise.all([layout.helper_path, layout.admin_path, layout.installer_ui_path, codexLauncher].map((file) => chmod(file, 0o755)));
  const requirements = renderManagedRequirementsV1(layout);
  await writeFile(layout.requirements_file, requirements);
  const manifestText = await readFile(layout.release_manifest_path, "utf8");
  const cliPath = await realpath(path.join(candidate, "dist", "cli.js"));
  const cliWorkerPath = await realpath(path.join(candidate, "dist", "lib", "long-task-host-worker-runtime.js"));
  const cliRuntimeManifest = await runtimeIdentity.createManagedHostRuntimeManifestV1(cliPath);
  const sandboxLauncher = await runtimeIdentity.resolveManagedSandboxLauncherV1(layout.helper_path, "linux");
  const bytesHash = async (file) => codec.sha256Hex(await readFile(file));
  const config = {
    schema_version: "ty-context-host-service-config-v1", state_root: layout.state_root, endpoint: layout.endpoint, managed_dir: layout.managed_dir,
    requirements_file: layout.requirements_file, node_path: await realpath(process.execPath), node_sha256: await bytesHash(process.execPath),
    helper_path: layout.helper_path, sandbox_launcher_path: sandboxLauncher.path, sandbox_launcher_sha256: sandboxLauncher.sha256,
    admin_path: layout.admin_path, admin_sha256: await bytesHash(layout.admin_path), installer_ui_path: layout.installer_ui_path, installer_ui_sha256: await bytesHash(layout.installer_ui_path),
    codex_launcher_path: codexLauncher, codex_launcher_sha256: await bytesHash(codexLauncher), cli_path: cliPath, cli_sha256: await bytesHash(cliPath),
    cli_worker_path: cliWorkerPath, cli_worker_sha256: await bytesHash(cliWorkerPath), cli_runtime_manifest: cliRuntimeManifest,
    cli_runtime_manifest_sha256: runtimeIdentity.managedHostRuntimeManifestSha256V1(cliRuntimeManifest), hook_path: layout.hook_path, hook_sha256: await bytesHash(layout.hook_path),
    worker_path: layout.worker_path, worker_sha256: await bytesHash(layout.worker_path), attestation_public_key_path: layout.attestation_public_key_path,
    managed_policy_sha256: sha256(requirements), release_manifest_sha256: sha256(manifestText), test_namespace: false
  };
  await writeFile(layout.service_config_path, canonical(config));
  await Promise.all([chmod(layout.managed_dir, 0o755), chmod(layout.state_root, 0o700), chmod(layout.requirements_file, 0o644), chmod(path.dirname(layout.endpoint), 0o755), ...[layout.hook_path, layout.worker_path, path.join(layout.managed_dir, "requirements.toml"), layout.release_root_public_key_path, layout.release_manifest_path, layout.release_signature_path, layout.service_config_path].map((file) => chmod(file, 0o644))]);
  const service = spawn(layout.helper_path, ["serve", "--config", layout.service_config_path], { stdio: ["ignore", "ignore", "inherit"] });
  await waitFor(layout.attestation_public_key_path, service);
  const ready = { schema_version: "ty-context-managed-host-test-ready-v1", codex_launcher: codexLauncher, codex_script: codexScript, hook_path: layout.hook_path };
  await writeFile(readyPath, canonical(ready));
  return { ready, async close() { if (service.exitCode === null) { service.kill("SIGTERM"); await Promise.race([new Promise((resolve) => service.once("exit", resolve)), new Promise((resolve) => setTimeout(resolve, 3000))]); } await Promise.all([rm(readyPath, { force: true }), rm(root, { recursive: true, force: true }), rm(layout.managed_dir, { recursive: true, force: true }), rm(layout.state_root, { recursive: true, force: true }), rm(layout.requirements_file, { force: true }), rm(layout.endpoint, { force: true }), rm(codexLauncher, { force: true }), rm(codexScript, { force: true })]); } };
}

async function startWindowsManagedHost(candidate, source) {
  const moduleAt = (relative) => import(pathToFileURL(path.join(candidate, ...relative.split("/"))).href);
  const [{ managedHostLayout }, release, { LONG_TASK_HOST_RELEASE_ROOT_PUBLIC_KEY_PEM }, installer] = await Promise.all([
    moduleAt("dist/lib/long-task-managed-host-layout.js"),
    moduleAt("dist/lib/long-task-host-release.js"),
    moduleAt("dist/lib/long-task-host-release-root.js"),
    moduleAt("dist/lib/long-task-host-installer.js")
  ]);
  const layout = managedHostLayout("win32");
  await release.verifyHostReleaseDirectoryV1(source, LONG_TASK_HOST_RELEASE_ROOT_PUBLIC_KEY_PEM, { platform: "windows", arch: process.arch });
  const root = await mkdtemp(path.join(os.tmpdir(), "tyc-external-audit-host-"));
  const codexLauncher = path.join(root, "ty-context-external-audit-codex-launcher.exe");
  const codexScript = path.join(root, "ty-context-external-audit-codex-launcher.mjs");
  await cp(process.execPath, codexLauncher);
  await writeFile(codexScript, `import {spawnSync} from "node:child_process";const result=spawnSync(process.argv[2],process.argv.slice(3),{stdio:"inherit",windowsHide:true});process.exit(result.status??1);\n`);
  const cliPath = await realpath(path.join(candidate, "dist", "cli.js"));
  const cliWorkerPath = await realpath(path.join(candidate, "dist", "lib", "long-task-host-worker-runtime.js"));
  try {
    await installer.installManagedHostReleaseV1({ source, layout, cli_path: cliPath, cli_worker_path: cliWorkerPath, codex_launcher_path: codexLauncher, start_service: true });
    await waitFor(layout.attestation_public_key_path);
  } catch (error) {
    await rm(root, { recursive: true, force: true });
    throw error;
  }
  const ready = { schema_version: "ty-context-managed-host-test-ready-v1", codex_launcher: codexLauncher, codex_script: codexScript, hook_path: layout.hook_path };
  return {
    ready,
    async close() {
      await installer.uninstallManagedHostReleaseV1({ layout }).catch(() => undefined);
      await rm(root, { recursive: true, force: true });
    }
  };
}

async function waitFor(file, child) { for (let attempt = 0; attempt < 600; attempt += 1) { if (child && child.exitCode !== null) throw new Error(`managed_host_exited:${child.exitCode}`); try { await readFile(file); return; } catch {} await new Promise((resolve) => setTimeout(resolve, 25)); } throw new Error("managed_host_not_ready"); }
async function inContainer() { try { await readFile("/.dockerenv"); return true; } catch { return false; } }
async function permittedLinuxRoot() { return await inContainer() || process.env.GITHUB_ACTIONS === "true"; }

export const HOST_RELEASE_ROOT_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAwDZLzZB44IgAdmtaJ5FrNTBpInEipG1bXE1brqcAUs0=
-----END PUBLIC KEY-----
`;
export const HOST_RELEASE_ROOT_KEY_ID = "59d4e01a5ca1c015556772b06a370f93ca2e2369e42b65c8d5e6bfa5f5bfc8e9";
const MAX_ARCHIVE = 64 * 1024 * 1024;
const MAX_EXPANDED = 256 * 1024 * 1024;

export async function materializeVerifiedHostRelease({ archive, expectedSha256, platform, arch }) {
  if (!/^[a-f0-9]{64}$/u.test(expectedSha256)) hostFail("host_release_sha256_invalid");
  const link = await lstat(archive).catch(() => undefined);
  if (!link?.isFile() || link.isSymbolicLink() || link.size > MAX_ARCHIVE) hostFail("host_release_archive_invalid");
  const source = await realpath(archive); const bytes = await readFile(source);
  if (sha256(bytes) !== expectedSha256) hostFail("host_release_sha256_mismatch");
  const temporary = await mkdtemp(path.join(os.tmpdir(), "tyc-audit-host-release-"));
  try {
    const root = await extractHostArchive(bytes, temporary);
    const identity = await verifyHostDirectory(root, { archiveSha256: expectedSha256, platform, arch });
    return { root, identity, async close() { await rm(temporary, { recursive: true, force: true }); } };
  } catch (error) { await rm(temporary, { recursive: true, force: true }); throw error; }
}

export function assertHostReleasePolicy() {
  const der = createPublicKey(HOST_RELEASE_ROOT_PUBLIC_KEY_PEM).export({ type: "spki", format: "der" });
  if (sha256(der) !== HOST_RELEASE_ROOT_KEY_ID) hostFail("host_release_root_key_policy_invalid");
}

export async function verifyHostReleaseCandidateBinding(root, options) {
  const candidate = await realpath(options.candidateSource); const suffix = options.platform === "windows" ? ".exe" : "";
  for (const [releaseName, candidateFile] of [
    [`ty-context-host-helper${suffix}`, options.helper], [`ty-context-host-admin${suffix}`, options.admin], [`ty-context-host-installer-ui${suffix}`, options.installerUi],
    ["long-task-hook.mjs", path.join(candidate, ".codex", "ty-context-managed", "managed-host-gate", "long-task-hook.mjs")],
    ["ty-context-host-worker.mjs", path.join(candidate, ".codex", "ty-context-managed", "managed-host-gate", "ty-context-host-worker.mjs")]
  ]) await equalHostFile(path.join(root, releaseName), candidateFile, releaseName);
  for (const name of ["long-task-hook.mjs", "ty-context-host-worker.mjs"]) await equalHostFile(path.join(root, name), path.join(candidate, "packages", "ty-context", "assets", "managed-host-gate", name), `packaged-${name}`);
  const moduleAt = (relative) => import(pathToFileURL(path.join(candidate, ...relative.split("/"))).href);
  const [{ managedHostLayout }, { renderManagedRequirementsV1 }] = await Promise.all([moduleAt("packages/ty-context/dist/lib/long-task-managed-host-layout.js"), moduleAt("packages/ty-context/dist/lib/long-task-managed-requirements.js")]);
  const nodePlatform = options.platform === "windows" ? "win32" : options.platform === "macos" ? "darwin" : "linux";
  const nodePath = options.platform === "windows" ? "C:\\Program Files\\nodejs\\node.exe" : options.platform === "macos" && options.arch === "arm64" ? "/opt/homebrew/bin/node" : options.platform === "macos" ? "/usr/local/bin/node" : "/usr/bin/node";
  const layout = managedHostLayout(nodePlatform); const expected = renderManagedRequirementsV1({ ...layout, node_path: nodePath, unix_node_path: options.platform === "windows" ? "/usr/bin/node" : nodePath });
  if ((await readFile(path.join(root, "requirements.toml"), "utf8")) !== expected) hostFail("host_release_candidate_binding_mismatch:requirements.toml");
}

async function verifyHostDirectory(root, expected) {
  assertHostReleasePolicy();
  const publicPem = await readFile(path.join(root, "host-release-root-public.pem"), "utf8");
  const installed = createPublicKey(publicPem).export({ type: "spki", format: "der" }); const pinned = createPublicKey(HOST_RELEASE_ROOT_PUBLIC_KEY_PEM).export({ type: "spki", format: "der" });
  if (!Buffer.from(installed).equals(Buffer.from(pinned))) hostFail("host_release_root_key_mismatch");
  const manifestText = await readFile(path.join(root, "host-release-manifest.json"), "utf8"); let manifest; try { manifest = JSON.parse(manifestText); } catch { hostFail("host_release_manifest_invalid"); }
  hostExact(manifest, ["arch", "files", "platform", "protocol", "release_version", "schema_version"], "manifest");
  if (canonical(manifest) !== manifestText || manifest.schema_version !== "ty-context-host-release-v1" || manifest.release_version !== "0.4.0" || manifest.protocol !== "ty-context-host-rpc-v1" || manifest.platform !== expected.platform || manifest.arch !== expected.arch) hostFail("host_release_manifest_invalid");
  const signature = Buffer.from((await readFile(path.join(root, "host-release-manifest.sig"), "utf8")).trim(), "base64url");
  if (!verify(null, Buffer.from(manifestText), HOST_RELEASE_ROOT_PUBLIC_KEY_PEM, signature)) hostFail("host_release_signature_invalid");
  if (!Array.isArray(manifest.files) || manifest.files.length > 64) hostFail("host_release_manifest_files_invalid");
  const names = [];
  for (const item of manifest.files) {
    hostExact(item, ["path", "sha256", "size"], "manifest_file");
    if (!hostPortable(item.path) || !/^[a-f0-9]{64}$/u.test(item.sha256) || !Number.isSafeInteger(item.size) || item.size < 0 || item.size > 128 * 1024 * 1024) hostFail("host_release_manifest_file_invalid");
    const file = path.join(root, item.path); const info = await stat(file); const body = await readFile(file);
    if (!info.isFile() || body.length !== item.size || sha256(body) !== item.sha256) hostFail(`host_release_asset_mismatch:${item.path}`); names.push(item.path);
  }
  if (new Set(names).size !== names.length || names.join("\0") !== [...names].sort().join("\0")) hostFail("host_release_manifest_paths_invalid");
  const suffix = expected.platform === "windows" ? ".exe" : ""; const requiredFiles = ["requirements.toml", "long-task-hook.mjs", "ty-context-host-worker.mjs", `ty-context-host-helper${suffix}`, `ty-context-host-admin${suffix}`, `ty-context-host-installer-ui${suffix}`];
  for (const name of requiredFiles) if (!names.includes(name)) hostFail(`host_release_asset_missing:${name}`);
  const actual = (await readdir(root)).sort(); const allowed = [...names, "host-release-manifest.json", "host-release-manifest.sig", "host-release-root-public.pem"].sort();
  if (canonical(actual) !== canonical(allowed)) hostFail("host_release_unmanifested_asset");
  return { sha256: expected.archiveSha256, manifest_sha256: sha256(manifestText), root_key_id: HOST_RELEASE_ROOT_KEY_ID, platform: expected.platform, arch: expected.arch };
}

async function extractHostArchive(compressed, destination) {
  let archive; try { archive = gunzipSync(compressed, { maxOutputLength: MAX_EXPANDED }); } catch { hostFail("host_release_archive_gzip_invalid"); }
  if (archive.length < 1024 || archive.length % 512 !== 0) hostFail("host_release_archive_framing_invalid");
  const entries = []; let offset = 0; let terminal = false;
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (hostZero(header)) { if (!hostZero(archive.subarray(offset + 512, offset + 1024)) || !hostZero(archive.subarray(offset + 1024))) hostFail("host_release_archive_terminator_invalid"); terminal = true; break; }
    hostHeaderValid(header); if (![0, 48].includes(header[156])) hostFail("host_release_archive_entry_type_invalid");
    const size = hostOctal(header.subarray(124, 136)); const end = offset + 512 + size;
    if (size > 128 * 1024 * 1024 || entries.length >= 64 || end > archive.length) hostFail("host_release_archive_size_invalid");
    const raw = hostText(header.subarray(0, 100)); if (hostText(header.subarray(345, 500))) hostFail("host_release_archive_path_invalid"); const parts = raw.split("/");
    if (parts.length !== 2 || parts.some((part) => !hostPortable(part))) hostFail("host_release_archive_path_invalid");
    entries.push({ root: parts[0], name: parts[1], bytes: Buffer.from(archive.subarray(offset + 512, end)) }); offset = end + ((512 - (size % 512)) % 512);
  }
  if (!terminal || entries.length === 0 || new Set(entries.map((entry) => entry.name)).size !== entries.length || new Set(entries.map((entry) => entry.root)).size !== 1) hostFail("host_release_archive_entries_invalid");
  const releaseRoot = path.join(destination, entries[0].root); await mkdir(releaseRoot);
  for (const entry of entries) await writeFile(path.join(releaseRoot, entry.name), entry.bytes, { flag: "wx", mode: /^ty-context-host-(?:helper|admin|installer-ui)(?:\.exe)?$/u.test(entry.name) ? 0o755 : 0o644 });
  return releaseRoot;
}

function hostHeaderValid(header) { if (hostText(header.subarray(257, 263)) !== "ustar") hostFail("host_release_archive_format_invalid"); const wanted = hostOctal(header.subarray(148, 156)); const copy = Buffer.from(header); copy.fill(32, 148, 156); if (copy.reduce((sum, byte) => sum + byte, 0) !== wanted) hostFail("host_release_archive_checksum_invalid"); }
function hostPortable(value) { if (!value || value === "." || value === ".." || !/^[A-Za-z0-9._-]+$/u.test(value)) return false; return !/^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/iu.test(value); }
function hostOctal(bytes) { const value = hostText(bytes).trim(); if (!/^[0-7]+$/u.test(value)) hostFail("host_release_archive_octal_invalid"); const number = Number.parseInt(value, 8); if (!Number.isSafeInteger(number) || number < 0) hostFail("host_release_archive_octal_invalid"); return number; }
function hostText(bytes) { const end = bytes.indexOf(0); const raw = bytes.subarray(0, end < 0 ? bytes.length : end); const value = raw.toString("utf8"); if (!Buffer.from(value).equals(raw)) hostFail("host_release_archive_text_invalid"); return value.trimEnd(); }
function hostZero(bytes) { return bytes.every((byte) => byte === 0); }
function hostExact(value, keys, label) { if (!value || typeof value !== "object" || Array.isArray(value) || canonical(Object.keys(value).sort()) !== canonical([...keys].sort())) hostFail(`host_release_${label}_keys_invalid`); }
async function equalHostFile(left, right, label) { if (sha256(await readFile(left)) !== sha256(await readFile(await realpath(right)))) hostFail(`host_release_candidate_binding_mismatch:${label}`); }
function hostFail(code) { throw new Error(code); }
