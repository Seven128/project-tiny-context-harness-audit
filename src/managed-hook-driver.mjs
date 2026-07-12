import { spawn } from "node:child_process";
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { chmod, cp, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { canonical, runProcess, sha256 } from "./candidate-installer.mjs";

export async function acquireManagedHost(candidatePackageRoot) {
  const supplied = process.env.TY_CONTEXT_MANAGED_HOST_READY;
  if (supplied) return { ready: JSON.parse(await readFile(supplied, "utf8")), close: async () => {} };
  if (process.platform === "win32") return startWindowsManagedHost(candidatePackageRoot);
  if (process.platform !== "linux" || process.getuid?.() !== 0 || !await permittedLinuxRoot()) throw new Error("external_audit_managed_host_requires_linux_root_container_or_ready_descriptor");
  return startLinuxManagedHost(candidatePackageRoot);
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

async function startLinuxManagedHost(candidate) {
  const helper = required("TY_CONTEXT_HOST_HELPER_BIN");
  const admin = required("TY_CONTEXT_HOST_ADMIN_BIN");
  const installerUi = required("TY_CONTEXT_HOST_INSTALLER_UI_BIN");
  const releasePrivateKey = required("TY_CONTEXT_HOST_RELEASE_ROOT_PRIVATE_KEY");
  const moduleAt = (relative) => import(pathToFileURL(path.join(candidate, ...relative.split("/"))).href);
  const [{ managedHostLayout }, { renderManagedRequirementsV1 }, release, runtimeIdentity, codec] = await Promise.all([
    moduleAt("dist/lib/long-task-managed-host-layout.js"),
    moduleAt("dist/lib/long-task-managed-requirements.js"),
    moduleAt("dist/lib/long-task-host-release.js"),
    moduleAt("dist/lib/long-task-host-runtime-identity.js"),
    moduleAt("dist/lib/composite-campaign-codec.js")
  ]);
  const layout = managedHostLayout("linux");
  const root = await mkdtemp(path.join(os.tmpdir(), "tyc-external-audit-host-"));
  const readyPath = path.join(root, "managed-host-ready.json");
  const codexDirectory = "/usr/local/libexec";
  const codexLauncher = path.join(codexDirectory, "ty-context-external-audit-codex-launcher");
  const codexScript = path.join(codexDirectory, "ty-context-external-audit-codex-launcher.mjs");
  await Promise.all([rm(layout.managed_dir, { recursive: true, force: true }), rm(layout.state_root, { recursive: true, force: true }), rm(layout.requirements_file, { force: true }), rm(layout.endpoint, { force: true })]);
  await Promise.all([mkdir(layout.managed_dir, { recursive: true }), mkdir(layout.state_root, { recursive: true }), mkdir(path.dirname(layout.requirements_file), { recursive: true }), mkdir(path.dirname(layout.endpoint), { recursive: true }), mkdir(codexDirectory, { recursive: true })]);
  const assets = path.join(candidate, "assets", "managed-host-gate");
  await Promise.all([
    cp(helper, layout.helper_path), cp(admin, layout.admin_path), cp(installerUi, layout.installer_ui_path),
    cp(path.join(assets, "long-task-hook.mjs"), layout.hook_path), cp(path.join(assets, "ty-context-host-worker.mjs"), layout.worker_path), cp(process.execPath, codexLauncher)
  ]);
  await writeFile(codexScript, `import {spawnSync} from "node:child_process";const result=spawnSync(process.argv[2],process.argv.slice(3),{stdio:"inherit",windowsHide:true});process.exit(result.status??1);\n`);
  await Promise.all([layout.helper_path, layout.admin_path, layout.installer_ui_path, codexLauncher].map((file) => chmod(file, 0o755)));
  const requirements = renderManagedRequirementsV1(layout);
  await Promise.all([writeFile(path.join(layout.managed_dir, "requirements.toml"), requirements), writeFile(layout.requirements_file, requirements)]);
  const privateKey = createPrivateKey(await readFile(releasePrivateKey));
  await writeFile(layout.release_root_public_key_path, createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString());
  const manifest = await release.createUnsignedHostReleaseManifestV1(layout.managed_dir, "0.4.0-rc.1");
  const manifestText = release.canonicalHostReleaseManifestV1(manifest);
  await Promise.all([writeFile(layout.release_manifest_path, manifestText), writeFile(layout.release_signature_path, sign(null, Buffer.from(manifestText), privateKey).toString("base64url"))]);
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
  return { ready, async close() { if (service.exitCode === null) { service.kill("SIGTERM"); await Promise.race([new Promise((resolve) => service.once("exit", resolve)), new Promise((resolve) => setTimeout(resolve, 3000))]); } await Promise.all([rm(readyPath, { force: true }), rm(root, { recursive: true, force: true })]); } };
}

async function startWindowsManagedHost(candidate) {
  const helper = required("TY_CONTEXT_HOST_HELPER_BIN");
  const admin = required("TY_CONTEXT_HOST_ADMIN_BIN");
  const installerUi = required("TY_CONTEXT_HOST_INSTALLER_UI_BIN");
  const releasePrivateKey = required("TY_CONTEXT_HOST_RELEASE_ROOT_PRIVATE_KEY");
  const moduleAt = (relative) => import(pathToFileURL(path.join(candidate, ...relative.split("/"))).href);
  const [{ managedHostLayout }, { renderManagedRequirementsV1 }, release, installer] = await Promise.all([
    moduleAt("dist/lib/long-task-managed-host-layout.js"),
    moduleAt("dist/lib/long-task-managed-requirements.js"),
    moduleAt("dist/lib/long-task-host-release.js"),
    moduleAt("dist/lib/long-task-host-installer.js")
  ]);
  const layout = managedHostLayout("win32");
  const root = await mkdtemp(path.join(os.tmpdir(), "tyc-external-audit-host-"));
  const source = path.join(root, "release");
  const codexLauncher = path.join(root, "ty-context-external-audit-codex-launcher.exe");
  const codexScript = path.join(root, "ty-context-external-audit-codex-launcher.mjs");
  await mkdir(source, { recursive: true });
  const assets = path.join(candidate, "assets", "managed-host-gate");
  await Promise.all([
    cp(helper, path.join(source, "ty-context-host-helper.exe")),
    cp(admin, path.join(source, "ty-context-host-admin.exe")),
    cp(installerUi, path.join(source, "ty-context-host-installer-ui.exe")),
    cp(path.join(assets, "long-task-hook.mjs"), path.join(source, "long-task-hook.mjs")),
    cp(path.join(assets, "ty-context-host-worker.mjs"), path.join(source, "ty-context-host-worker.mjs")),
    cp(process.execPath, codexLauncher)
  ]);
  await writeFile(codexScript, `import {spawnSync} from "node:child_process";const result=spawnSync(process.argv[2],process.argv.slice(3),{stdio:"inherit",windowsHide:true});process.exit(result.status??1);\n`);
  const requirements = renderManagedRequirementsV1(layout);
  await writeFile(path.join(source, "requirements.toml"), requirements);
  const privateKey = createPrivateKey(await readFile(releasePrivateKey));
  const publicPem = createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString();
  await writeFile(path.join(source, "host-release-root-public.pem"), publicPem);
  const manifest = await release.createUnsignedHostReleaseManifestV1(source, "0.4.0-rc.1");
  const manifestText = release.canonicalHostReleaseManifestV1(manifest);
  await Promise.all([
    writeFile(path.join(source, "host-release-manifest.json"), manifestText),
    writeFile(path.join(source, "host-release-manifest.sig"), sign(null, Buffer.from(manifestText), privateKey).toString("base64url"))
  ]);
  const cliPath = await realpath(path.join(candidate, "dist", "cli.js"));
  const cliWorkerPath = await realpath(path.join(candidate, "dist", "lib", "long-task-host-worker-runtime.js"));
  try {
    await installer.installManagedHostReleaseV1({ source, layout, pinned_root_public_key: publicPem, cli_path: cliPath, cli_worker_path: cliWorkerPath, codex_launcher_path: codexLauncher, start_service: true });
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
function required(name) { const value = process.env[name]; if (!value) throw new Error(`missing_${name}`); return value; }
