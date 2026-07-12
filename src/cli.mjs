#!/usr/bin/env node
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runAttackMatrix } from "./black-box-runner.mjs";
import { canonical, installCandidate, sha256, sha256File } from "./candidate-installer.mjs";
import { runConsumerLab } from "./consumer-lab.mjs";
import { acquireManagedHost } from "./managed-hook-driver.mjs";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(await readFile(path.join(packageRoot, "package.json"), "utf8"));
const expected = JSON.parse(await readFile(path.join(packageRoot, "expected-outcomes.json"), "utf8"));

if (process.argv.includes("--self-test")) {
  assertSelf();
  process.stdout.write("external_audit_self_test=passed\n");
  process.exit(0);
}

if (option("--resign-result")) {
  await resignResult();
  process.exit(0);
}

const candidateTarball = path.resolve(requiredOption("--candidate"));
const candidateSha256 = requiredOption("--candidate-sha256");
const auditIntegrity = requiredOption("--audit-integrity");
const resultPath = path.resolve(requiredOption("--result"));
const signingKeyPath = path.resolve(requiredOption("--signing-key"));
const expectedKeyId = requiredOption("--signing-key-id");
const diagnosticFilter = process.env.TY_CONTEXT_AUDIT_FILTER;
if (!/^[a-f0-9]{64}$/u.test(candidateSha256) || !/^sha512-[A-Za-z0-9+/]+={0,2}$/u.test(auditIntegrity)) throw new Error("external_audit_identity_argument_invalid");
if (await sha256File(candidateTarball) !== candidateSha256) throw new Error("candidate_sha256_mismatch");

const root = await mkdtemp(path.join(os.tmpdir(), "tyc-external-audit-"));
let host;
let failed = false;
try {
  const base = await installCandidate(path.join(root, "base-candidate"), candidateTarball, candidateSha256);
  host = await acquireManagedHost(base.packageRoot);
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
  process.stdout.write(`external_audit_result=${resultPath}\n`);
} finally {
  await host?.close();
  await rm(root, { recursive: true, force: true });
}
if (failed || diagnosticFilter) process.exitCode = 1;

function assertSelf() {
  if (manifest.name !== "project-tiny-context-harness-audit" || manifest.version !== "0.1.0") throw new Error("external_audit_package_identity_invalid");
  if (expected.schema_version !== "external-audit-expected-outcomes-v1" || expected.attacks.length !== 8 || expected.consumers.length !== 6) throw new Error("external_audit_expected_outcomes_invalid");
  const ids = [...expected.attacks, ...expected.consumers].map((item) => item.id);
  if (new Set(ids).size !== ids.length) throw new Error("external_audit_expected_outcomes_duplicate");
}
async function resignResult() {
  const inputPath = path.resolve(requiredOption("--resign-result"));
  const candidateSha256 = requiredOption("--candidate-sha256");
  const auditIntegrity = requiredOption("--audit-integrity");
  const resultPath = path.resolve(requiredOption("--result"));
  const signingKeyPath = path.resolve(requiredOption("--signing-key"));
  const expectedKeyId = requiredOption("--signing-key-id");
  const input = JSON.parse(await readFile(inputPath, "utf8"));
  if (input?.schema_version !== "external-audit-result-v1" || !input.payload) throw new Error("external_audit_resign_input_invalid");
  validatePassingFullPayload(input.payload, auditIntegrity, candidateSha256);
  const privateKey = createPrivateKey(await readFile(signingKeyPath));
  const publicDer = createPublicKey(privateKey).export({ type: "spki", format: "der" });
  const keyId = sha256(publicDer);
  if (keyId !== expectedKeyId) throw new Error("external_audit_signing_key_mismatch");
  const envelope = { schema_version: "external-audit-result-v1", payload: input.payload, signature: { algorithm: "Ed25519", key_id: keyId, value: sign(null, Buffer.from(canonical(input.payload)), privateKey).toString("base64url") } };
  await mkdir(path.dirname(resultPath), { recursive: true });
  await writeFile(resultPath, `${canonical(envelope)}\n`, { flag: "wx" });
  process.stdout.write(`external_audit_resigned_result=${resultPath}\n`);
}
function validatePassingFullPayload(payload, auditIntegrity, candidateSha256) {
  if (payload.schema_version !== "external-audit-result-payload-v1" || payload.audit_package?.name !== manifest.name || payload.audit_package?.version !== manifest.version || payload.audit_package?.integrity !== auditIntegrity) throw new Error("external_audit_payload_identity_invalid");
  if (payload.expected_outcomes_sha256 !== sha256(canonical(expected)) || payload.execution_scope !== "full" || payload.overall_status !== "passed") throw new Error("external_audit_payload_scope_invalid");
  if (!/^[a-f0-9]{64}$/u.test(candidateSha256) || payload.candidate?.name !== "project-tiny-context-harness" || payload.candidate?.sha256 !== candidateSha256) throw new Error("external_audit_candidate_identity_invalid");
  if (!Array.isArray(payload.attacks) || payload.attacks.length !== expected.attacks.length || !Array.isArray(payload.consumers) || payload.consumers.length !== expected.consumers.length) throw new Error("external_audit_payload_case_set_invalid");
  for (let index = 0; index < expected.attacks.length; index += 1) {
    const wanted = expected.attacks[index]; const actual = payload.attacks[index];
    if (actual?.id !== wanted.id || actual.expected_status !== wanted.expected_status || actual.expected_code !== wanted.expected_code || actual.actual_status !== wanted.expected_status || actual.actual_code !== wanted.expected_code || actual.passed !== true) throw new Error(`external_audit_attack_failed:${wanted.id}`);
  }
  for (let index = 0; index < expected.consumers.length; index += 1) {
    const wanted = expected.consumers[index]; const actual = payload.consumers[index];
    if (actual?.id !== wanted.id || actual.expected_status !== wanted.expected_status || actual.actual_status !== wanted.expected_status || actual.passed !== true) throw new Error(`external_audit_consumer_failed:${wanted.id}`);
  }
}
function option(name) { const index = process.argv.indexOf(name); return index < 0 ? undefined : process.argv[index + 1]; }
function requiredOption(name) { const value = option(name); if (!value) throw new Error(`missing_${name.slice(2).replace(/-/gu, "_")}`); return value; }
