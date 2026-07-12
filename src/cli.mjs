#!/usr/bin/env node
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runAttackMatrix } from "./black-box-runner.mjs";
import { canonical, grantCandidateTree, installCandidate, prepareCandidateHome, runProcess, sealCandidateTree, secureAuditRoot, sha256, sha256File } from "./candidate-installer.mjs";
import { runConsumerLab } from "./consumer-lab.mjs";
import { acquireManagedHost, assertHostReleasePolicy, materializeVerifiedHostRelease, verifyHostReleaseCandidateBinding } from "./managed-hook-driver.mjs";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(await readFile(path.join(packageRoot, "package.json"), "utf8"));
const expected = JSON.parse(await readFile(path.join(packageRoot, "expected-outcomes.json"), "utf8"));

if (process.argv.includes("--self-test")) {
  await assertSelf();
  assertHostReleasePolicy();
  process.stdout.write("external_audit_self_test=passed\n");
  process.exit(0);
}

if (option("--verify-host-release-candidate")) {
  await verifyHostReleaseCandidate();
  process.exit(0);
}

if (option("--bind-candidate-artifact")) {
  assertCandidateController();
  await bindCandidateArtifact();
  process.exit(0);
}

if (option("--build-host-candidate")) {
  assertCandidateController();
  await buildHostCandidate();
  process.exit(0);
}

if (option("--resign-result")) {
  await resignResult();
  process.exit(0);
}

const candidateSourceTarball = path.resolve(requiredOption("--candidate"));
assertCandidateController();
const candidateSha256 = requiredOption("--candidate-sha256");
const auditIntegrity = requiredOption("--audit-integrity");
const requestedResultPath = path.resolve(requiredOption("--result"));
const signingKeyPath = path.resolve(requiredOption("--signing-key"));
const expectedKeyId = requiredOption("--signing-key-id");
const hostReleaseArchive = path.resolve(requiredOption("--host-release"));
const hostReleaseSha256 = requiredOption("--host-release-sha256");
const diagnosticFilter = process.env.TY_CONTEXT_AUDIT_FILTER;
if (!/^[a-f0-9]{64}$/u.test(candidateSha256) || !/^sha512-[A-Za-z0-9+/]+={0,2}$/u.test(auditIntegrity)) throw new Error("external_audit_identity_argument_invalid");
if (await sha256File(candidateSourceTarball) !== candidateSha256) throw new Error("candidate_sha256_mismatch");

const root = await mkdtemp(path.join(os.tmpdir(), "tyc-external-audit-"));
await secureAuditRoot(root);
const candidateTarball = path.join(root, "candidate.tgz"); await copyFile(candidateSourceTarball, candidateTarball);
const resultPath = path.join(root, "provisional-result.json");
const candidateHome = await prepareCandidateHome(path.join(root, "candidate-home"));
process.env.HOME = candidateHome; process.env.USERPROFILE = candidateHome; process.env.NPM_CONFIG_CACHE = path.join(candidateHome, ".npm");
let host;
let hostRelease;
let failed = false;
try {
  const base = await installCandidate(path.join(root, "base-candidate"), candidateTarball, candidateSha256);
  hostRelease = await materializeVerifiedHostRelease({ archive: hostReleaseArchive, expectedSha256: hostReleaseSha256, platform: platformName(), arch: process.arch });
  host = await acquireManagedHost(base.packageRoot, hostRelease.root, { allowReadyDescriptor: Boolean(diagnosticFilter) });
  const attacksExpected = diagnosticFilter ? expected.attacks.filter((item) => item.id === diagnosticFilter) : expected.attacks;
  const consumersExpected = diagnosticFilter ? expected.consumers.filter((item) => item.id === diagnosticFilter) : expected.consumers;
  if (diagnosticFilter && attacksExpected.length + consumersExpected.length !== 1) throw new Error(`external_audit_filter_unknown:${diagnosticFilter}`);
  const attacks = await runAttackMatrix({ tarball: candidateTarball, candidateSha256, ready: host.ready, expected: attacksExpected });
  const consumers = await runConsumerLab({ tarball: candidateTarball, candidateSha256, ready: host.ready, expected: consumersExpected });
  failed = [...attacks, ...consumers].some((item) => item.passed !== true);
  const payload = {
    schema_version: "external-audit-result-payload-v1",
    audit_package: { name: manifest.name, version: manifest.version, integrity: auditIntegrity },
    expected_outcomes_sha256: sha256(canonical(expected)),
    candidate: { name: "project-tiny-context-harness", version: base.version, sha256: candidateSha256 },
    platform: { platform: process.platform, arch: process.arch, node: process.version },
    host_release: hostRelease.identity,
    execution_scope: diagnosticFilter ? `diagnostic:${diagnosticFilter}` : "full",
    attacks,
    consumers,
    overall_status: failed ? "failed" : "passed",
    completed_at: new Date().toISOString()
  };
  const privateKey = createPrivateKey(await readFile(signingKeyPath));
  const publicDer = createPublicKey(privateKey).export({ type: "spki", format: "der" });
  const keyId = sha256(publicDer);
  if (keyId !== expectedKeyId) throw new Error("external_audit_signing_key_mismatch");
  const envelope = { schema_version: "external-audit-result-v1", payload, signature: { algorithm: "Ed25519", key_id: keyId, value: sign(null, Buffer.from(canonical(payload)), privateKey).toString("base64url") } };
  await mkdir(path.dirname(resultPath), { recursive: true });
  await writeFile(resultPath, `${canonical(envelope)}\n`, { flag: "wx" });
  await mkdir(path.dirname(requestedResultPath), { recursive: true }); await copyFile(resultPath, requestedResultPath, 1);
  process.stdout.write(`external_audit_result=${requestedResultPath}\n`);
} finally {
  await host?.close();
  await hostRelease?.close();
  await rm(root, { recursive: true, force: true });
}
if (failed || diagnosticFilter) process.exitCode = 1;

async function assertSelf() {
  if (manifest.name !== "project-tiny-context-harness-audit" || manifest.version !== "0.1.0") throw new Error("external_audit_package_identity_invalid");
  if (expected.schema_version !== "external-audit-expected-outcomes-v1" || expected.attacks.length !== 8 || expected.consumers.length !== 6) throw new Error("external_audit_expected_outcomes_invalid");
  const ids = [...expected.attacks, ...expected.consumers].map((item) => item.id);
  if (new Set(ids).size !== ids.length) throw new Error("external_audit_expected_outcomes_duplicate");
  const sources = (await readdir(path.join(packageRoot, "src"))).sort();
  if (canonical(sources) !== canonical(["black-box-runner.mjs", "candidate-installer.mjs", "cli.mjs", "consumer-lab.mjs", "managed-hook-driver.mjs"].sort())) throw new Error("external_audit_source_surface_invalid");
  const driver = await readFile(path.join(packageRoot, "src", "managed-hook-driver.mjs"), "utf8");
  const installer = await readFile(path.join(packageRoot, "src", "candidate-installer.mjs"), "utf8");
  if (/HOST_RELEASE_ROOT_PRIVATE_KEY|host-release-root-private|moduleAt\(|pathToFileURL/u.test(driver) || !driver.includes("linuxCandidateIdentity") || !driver.includes("runtimeManifest")) throw new Error("external_audit_privileged_host_boundary_invalid");
  if (!installer.includes("candidateEnvironment") || !installer.includes("runWindowsCandidate") || !installer.includes("uid: identity.uid") || !installer.includes("terminateCandidateProcesses") || !installer.includes("sealCandidateTree")) throw new Error("external_audit_unprivileged_candidate_boundary_invalid");
  const workflow = await readFile(path.join(packageRoot, ".github", "workflows", "audit-candidate.yml"), "utf8").catch(() => "");
  if (workflow && (!workflow.includes("linux_host_release_url") || !workflow.includes("--host-release-sha256") || !workflow.includes("unprivileged candidate identity") || !workflow.includes("--npm-cli") || !workflow.includes("--cargo-bin") || !workflow.includes("TY_CONTEXT_AUDIT_CARGO_BIN") || !workflow.includes("x86_64-pc-windows-gnullvm") || !workflow.includes("Remove temporary Windows candidate identity") || /HOST_RELEASE_ROOT_PRIVATE_KEY|host-release-root-private/u.test(workflow))) throw new Error("external_audit_workflow_host_release_boundary_invalid");
}
async function verifyHostReleaseCandidate() {
  const hostRelease = await materializeVerifiedHostRelease({
    archive: path.resolve(requiredOption("--verify-host-release-candidate")),
    expectedSha256: requiredOption("--host-release-sha256"),
    platform: platformName(),
    arch: process.arch
  });
  try {
    await verifyHostReleaseCandidateBinding(hostRelease.root, {
      candidateSource: path.resolve(requiredOption("--candidate-source")),
      helper: path.resolve(requiredOption("--helper")),
      admin: path.resolve(requiredOption("--admin")),
      installerUi: path.resolve(requiredOption("--installer-ui")),
      platform: platformName(),
      arch: process.arch
    });
    process.stdout.write(`host_release_candidate_binding=passed sha256=${hostRelease.identity.sha256}\n`);
  } finally { await hostRelease.close(); }
}
async function bindCandidateArtifact() {
  const source = path.resolve(requiredOption("--candidate-source")); const candidate = path.resolve(requiredOption("--bind-candidate-artifact")); const expectedSha256 = requiredOption("--candidate-sha256"); const output = path.resolve(requiredOption("--output-dir")); const npmCli = await realFileOption("--npm-cli");
  if (!/^[a-f0-9]{64}$/u.test(expectedSha256) || await sha256File(candidate) !== expectedSha256) throw new Error("candidate_sha256_mismatch");
  await grantCandidateTree(source); await mkdir(output, { recursive: true }); await grantCandidateTree(output); const home = await prepareCandidateHome(path.join(output, ".candidate-home")); const childEnv = { ...process.env, HOME: home, USERPROFILE: home, NPM_CONFIG_CACHE: path.join(home, ".npm") };
  try { for (const [args, timeout] of [[["ci", "--ignore-scripts"], 10 * 60_000], [["run", "build", "--workspace", "project-tiny-context-harness"], 10 * 60_000], [["pack", "--silent", "--ignore-scripts", "--workspace", "project-tiny-context-harness", "--pack-destination", output], 10 * 60_000]]) { const result = await runProcess(process.execPath, [npmCli, ...args], { cwd: source, env: childEnv, timeoutMs: timeout }); if (result.status !== 0) throw new Error(`candidate_rebuild_failed:${result.stderr}`); } } finally { await sealCandidateTree(source); await sealCandidateTree(output); }
  const archives = (await readdir(output)).filter((name) => name.endsWith(".tgz")); if (archives.length !== 1) throw new Error("candidate_rebuild_archive_invalid");
  const rebuiltSha256 = await sha256File(path.join(output, archives[0])); if (rebuiltSha256 !== expectedSha256) throw new Error("candidate_tarball_does_not_match_commit");
  process.stdout.write(`candidate_commit_binding=passed sha256=${rebuiltSha256}\n`);
}
async function buildHostCandidate() {
  const source = path.resolve(requiredOption("--build-host-candidate")); const cargoBin = await realFileOption("--cargo-bin"); const target = requiredOption("--target"); const wanted = process.platform === "win32" ? "x86_64-pc-windows-gnullvm" : process.platform === "linux" ? "x86_64-unknown-linux-gnu" : ""; if (target !== wanted) throw new Error("candidate_host_target_invalid"); await grantCandidateTree(source); const home = await prepareCandidateHome(path.join(source, ".tyc-audit-build-home")); const childEnv = { ...process.env, HOME: home, USERPROFILE: home };
  const manifestPath = path.join(source, "host", "ty-context-host-helper", "Cargo.toml"); let result; try { result = await runProcess(cargoBin, ["build", "--release", "--locked", "--target", target, "--manifest-path", manifestPath], { cwd: source, env: childEnv, timeoutMs: 20 * 60_000 }); } finally { await sealCandidateTree(source); }
  if (result.status !== 0) throw new Error(`candidate_host_build_failed:${result.stderr}`); process.stdout.write("candidate_host_build=passed\n");
}
async function resignResult() {
  const inputPath = path.resolve(requiredOption("--resign-result"));
  const candidateSha256 = requiredOption("--candidate-sha256");
  const auditIntegrity = requiredOption("--audit-integrity");
  const resultPath = path.resolve(requiredOption("--result"));
  const signingKeyPath = path.resolve(requiredOption("--signing-key"));
  const expectedKeyId = requiredOption("--signing-key-id");
  const hostReleaseSha256 = requiredOption("--host-release-sha256");
  const input = JSON.parse(await readFile(inputPath, "utf8"));
  if (input?.schema_version !== "external-audit-result-v1" || !input.payload) throw new Error("external_audit_resign_input_invalid");
  validatePassingFullPayload(input.payload, auditIntegrity, candidateSha256, hostReleaseSha256);
  const privateKey = createPrivateKey(await readFile(signingKeyPath));
  const publicDer = createPublicKey(privateKey).export({ type: "spki", format: "der" });
  const keyId = sha256(publicDer);
  if (keyId !== expectedKeyId) throw new Error("external_audit_signing_key_mismatch");
  const envelope = { schema_version: "external-audit-result-v1", payload: input.payload, signature: { algorithm: "Ed25519", key_id: keyId, value: sign(null, Buffer.from(canonical(input.payload)), privateKey).toString("base64url") } };
  await mkdir(path.dirname(resultPath), { recursive: true });
  await writeFile(resultPath, `${canonical(envelope)}\n`, { flag: "wx" });
  process.stdout.write(`external_audit_resigned_result=${resultPath}\n`);
}
function validatePassingFullPayload(payload, auditIntegrity, candidateSha256, hostReleaseSha256) {
  exact(payload, ["attacks", "audit_package", "candidate", "completed_at", "consumers", "execution_scope", "expected_outcomes_sha256", "host_release", "overall_status", "platform", "schema_version"], "payload");
  exact(payload.audit_package, ["integrity", "name", "version"], "audit_package"); exact(payload.candidate, ["name", "sha256", "version"], "candidate"); exact(payload.platform, ["arch", "node", "platform"], "platform"); exact(payload.host_release, ["arch", "manifest_sha256", "platform", "root_key_id", "sha256"], "host_release");
  if (payload.schema_version !== "external-audit-result-payload-v1" || payload.audit_package?.name !== manifest.name || payload.audit_package?.version !== manifest.version || payload.audit_package?.integrity !== auditIntegrity) throw new Error("external_audit_payload_identity_invalid");
  if (payload.expected_outcomes_sha256 !== sha256(canonical(expected)) || payload.execution_scope !== "full" || payload.overall_status !== "passed") throw new Error("external_audit_payload_scope_invalid");
  if (!/^[a-f0-9]{64}$/u.test(candidateSha256) || payload.candidate?.name !== "project-tiny-context-harness" || payload.candidate?.version !== "0.4.0" || payload.candidate?.sha256 !== candidateSha256) throw new Error("external_audit_candidate_identity_invalid");
  if (!["linux", "win32"].includes(payload.platform?.platform) || payload.platform?.arch !== "x64" || !/^v24\./u.test(payload.platform?.node ?? "") || !Number.isFinite(Date.parse(payload.completed_at))) throw new Error("external_audit_platform_identity_invalid");
  if (!/^[a-f0-9]{64}$/u.test(hostReleaseSha256) || payload.host_release?.sha256 !== hostReleaseSha256 || payload.host_release?.root_key_id !== "59d4e01a5ca1c015556772b06a370f93ca2e2369e42b65c8d5e6bfa5f5bfc8e9" || payload.host_release?.platform !== platformName(payload.platform?.platform) || payload.host_release?.arch !== payload.platform?.arch || !/^[a-f0-9]{64}$/u.test(payload.host_release?.manifest_sha256 ?? "")) throw new Error("external_audit_host_release_identity_invalid");
  if (!Array.isArray(payload.attacks) || payload.attacks.length !== expected.attacks.length || !Array.isArray(payload.consumers) || payload.consumers.length !== expected.consumers.length) throw new Error("external_audit_payload_case_set_invalid");
  for (let index = 0; index < expected.attacks.length; index += 1) {
    const wanted = expected.attacks[index]; const actual = payload.attacks[index];
    exact(actual, ["actual_code", "actual_status", "duration_ms", "evidence_sha256", "expected_code", "expected_status", "id", "passed"], `attack:${wanted.id}`);
    if (actual?.id !== wanted.id || actual.expected_status !== wanted.expected_status || actual.expected_code !== wanted.expected_code || actual.actual_status !== wanted.expected_status || actual.actual_code !== wanted.expected_code || actual.passed !== true || !nonnegative(actual.duration_ms) || !hex(actual.evidence_sha256)) throw new Error(`external_audit_attack_failed:${wanted.id}`);
  }
  for (let index = 0; index < expected.consumers.length; index += 1) {
    const wanted = expected.consumers[index]; const actual = payload.consumers[index];
    exact(actual, ["actual_code", "actual_status", "browser_key", "dependency_key", "duration_ms", "evidence_sha256", "expected_status", "finding_codes", "id", "manager", "passed"], `consumer:${wanted.id}`);
    const browser = wanted.id === "playwright";
    if (actual?.id !== wanted.id || actual.expected_status !== wanted.expected_status || actual.actual_status !== wanted.expected_status || actual.actual_code !== "ok" || actual.passed !== true || actual.manager !== "npm" || !hex(actual.dependency_key) || (browser ? !hex(actual.browser_key) : actual.browser_key !== null) || !Array.isArray(actual.finding_codes) || actual.finding_codes.length !== 0 || !nonnegative(actual.duration_ms) || !hex(actual.evidence_sha256)) throw new Error(`external_audit_consumer_failed:${wanted.id}`);
  }
}
function option(name) { const index = process.argv.indexOf(name); return index < 0 ? undefined : process.argv[index + 1]; }
function requiredOption(name) { const value = option(name); if (!value) throw new Error(`missing_${name.slice(2).replace(/-/gu, "_")}`); return value; }
async function realFileOption(name) { const file = await realpath(path.resolve(requiredOption(name))); if (!(await stat(file)).isFile()) throw new Error(`invalid_${name.slice(2).replace(/-/gu, "_")}`); return file; }
function platformName(value = process.platform) { if (value === "win32") return "windows"; if (value === "darwin") return "macos"; if (value === "linux" || value === "windows" || value === "macos") return value; throw new Error("external_audit_platform_unsupported"); }
function exact(value, keys, label) { if (!value || typeof value !== "object" || Array.isArray(value) || canonical(Object.keys(value).sort()) !== canonical([...keys].sort())) throw new Error(`external_audit_${label}_keys_invalid`); }
function hex(value) { return typeof value === "string" && /^[a-f0-9]{64}$/u.test(value); }
function nonnegative(value) { return Number.isInteger(value) && value >= 0; }
function assertCandidateController() { if (process.platform === "win32") { if (!process.env.TY_CONTEXT_AUDIT_WINDOWS_USER || !process.env.TY_CONTEXT_AUDIT_WINDOWS_PASSWORD) throw new Error("external_audit_windows_candidate_identity_required"); return; } if (process.platform !== "linux" || process.getuid?.() !== 0) throw new Error("external_audit_privileged_controller_required"); const uid = Number(process.env.TY_CONTEXT_AUDIT_CANDIDATE_UID); const gid = Number(process.env.TY_CONTEXT_AUDIT_CANDIDATE_GID); if (!Number.isInteger(uid) || uid <= 0 || !Number.isInteger(gid) || gid <= 0) throw new Error("external_audit_candidate_identity_required"); }
