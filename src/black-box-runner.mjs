import { execFile } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { grantCandidateTree, installCandidate, runProcess, safeCode, sha256 } from "./candidate-installer.mjs";
import { invokeManagedHook } from "./managed-hook-driver.mjs";

const exec = promisify(execFile);

export async function runAttackMatrix({ tarball, candidateSha256, ready, expected }) {
  const handlers = attackHandlers(); const results = [];
  for (const row of expected) {
    const started = Date.now(); let actual;
    try { const handler = handlers.get(row.id); if (!handler) throw new Error(`external_case_missing:${row.id}`); actual = await handler(row, { tarball, candidateSha256, ready }); }
    catch (error) { actual = { status: "audit_error", code: safeCode(error instanceof Error ? error.message : error), evidence: String(error instanceof Error ? error.message : error) }; }
    const passed = actual.status === row.expected_status && actual.code === row.expected_code;
    results.push({ id: row.id, expected_status: row.expected_status, expected_code: row.expected_code, actual_status: actual.status, actual_code: actual.code, passed, duration_ms: Date.now() - started, evidence_sha256: sha256(actual.evidence ?? `${actual.status}:${actual.code}`) });
  }
  return results;
}

export async function createAuditRuntime(row, options, settings = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), `tyc-external-${row.id}-`));
  if (process.platform !== "win32") await chmod(root, 0o711);
  const repository = path.join(root, "project"); const install = path.join(root, "candidate");
  const candidate = await installCandidate(install, options.tarball, options.candidateSha256);
  const workdir = await writeBaseContract(repository, settings);
  return {
    row, root, repository, workdir, candidate,
    path(relative) { return path.join(repository, ...relative.split("/")); },
    taskPath(relative) { return path.join(workdir, ...relative.split("/")); },
    async cli(command, extra = [], config = {}) { if (config.heartbeat !== false) await invokeManagedHook(options.ready, repository, "SessionStart", { source: "resume" }); return runProcess(process.execPath, [candidate.cliPath, "composite-long-task", command, config.workdir ?? workdir, ...extra], { cwd: repository, timeoutMs: config.timeoutMs ?? 240_000, env: { ...process.env, NO_COLOR: "1" } }); },
    hook(event, input = {}) { return invokeManagedHook(options.ready, repository, event, input); },
    async cleanup() { if(process.env.TY_CONTEXT_AUDIT_KEEP!=="1")await rm(root, { recursive: true, force: true }); }
  };
}

export function baseContractData() {
  return {
    product: { schema_version: "product-source-v3", product_goal: "Deliver independently audited capability", delivery_scope: "system_capability_build", full_population_required: false, owner_surfaces: [{ id: "OS-RUNTIME", kind: "runtime", location: "value-reader", primary_action: "read-value", expected_feedback: "good-visible" }], requirements: [{ id: "PR-001", statement: "Capability works", observable_outcome: "Oracle observes the product value", owner_boundary: "runtime", owner_surface_refs: ["OS-RUNTIME"], context_refs: ["project_context/context.toml"], population_policy: "not_applicable" }], boundaries: [{ id: "PB-001", rule: "No shortcut", requirement_refs: ["PR-001"] }], non_completing_outcomes: [{ id: "NCO-001", forbidden_outcome: "No-op", requirement_refs: ["PR-001"] }], population_exclusion_rules: [], representative_samples_validate: [], representative_samples_do_not_validate: [], out_of_scope_backlog: [] },
    plan: { schema_version: "technical-plan-v3", plan_items: [{ id: "PI-001", title: "Implement audited behavior", implementation_notes: [], obligations: [{ id: "PI-001-OB-001", statement: "Implement behavior", source_requirement_ids: ["PR-001"], implementation_bindings: [{ id: "IB-001", kind: "file", target: "src/value.txt", verification: { mode: "harness_static" } }, { id: "IB-002", kind: "runtime_capability", target: "value.read", verification: { mode: "oracle_observation", spec_id: "VS-AC-001", observation_id: "works" } }], forbidden_shortcuts: [{ id: "FS-001", statement: "No no-op", source_boundary_ids: ["PB-001"], source_non_completing_ids: ["NCO-001"] }], related_ac_ids: ["AC-001"], counterfactual_control_ids: ["CF-PI-001-OB-001"] }] }], counterfactual_controls: [{ id: "CF-PI-001-OB-001", obligation_ids: ["PI-001-OB-001"], mutation: { type: "remove_binding_targets", binding_ids: ["IB-001"] }, expected_failed_assertion_ids: ["PA-001"] }] },
    checklist: { schema_version: "acceptance-checklist-v3", counterexample_fixtures: [], proof_requirements: [{ id: "PRF-AC-001-RUNTIME", proof_surface: "runtime_behavior", obligation_refs: ["PI-001-OB-001"], owner_surface_refs: ["OS-RUNTIME"], verification_spec_ids: ["VS-AC-001"] }], acceptance_criteria: [{ id: "AC-001", title: "Runtime works", obligation_refs: ["PI-001-OB-001"], validates: ["runtime behavior"], does_not_validate: ["unrelated behavior"], proof_requirement_refs: ["PRF-AC-001-RUNTIME"], verification_spec_ids: ["VS-AC-001"] }], verification_specs: [{ id: "VS-AC-001", runner_type: "node_oracle", proof_capabilities: ["runtime_behavior"], claims: { requirement_ids: ["PR-001"], plan_item_ids: ["PI-001"], obligation_ids: ["PI-001-OB-001"], binding_ids: ["IB-001", "IB-002"], ac_ids: ["AC-001"], proof_requirement_ids: ["PRF-AC-001-RUNTIME"] }, oracle: { entrypoint: "tests/acceptance/oracle.mjs" }, cwd: ".", timeout_ms: 180000, input_paths: ["src/**", "tests/acceptance/**"], artifact_globs: [], network_policy: { mode: "none", allowed_hosts: [] }, command_steps: [{ id: "CMD-001", tool: "node_script", target: "tests/acceptance/command.mjs", argv: [], cwd: ".", timeout_ms: 10000, environment_refs: [], output_artifact_ids: [] }], environment_refs: [], positive_assertions: [{ id: "PA-001", observation_id: "works", observation_kind: "runtime_behavior", operator: "equals", expected: { binding_id: "IB-002", capability: "value.read", value: "good" } }], negative_assertions: [{ id: "NA-001", observation_id: "forbidden", observation_kind: "scalar", operator: "not_equals", expected: "forbidden", source_boundary_ids: ["PB-001"], source_non_completing_ids: ["NCO-001"], source_forbidden_shortcut_ids: ["FS-001"] }], environment_requirements: [] }], environment_probes: [] }
  };
}

async function writeBaseContract(repository, settings) {
  const task = path.join(repository, "task");
  await Promise.all([mkdir(path.join(repository, "project_context"), { recursive: true }), mkdir(path.join(repository, "tests", "acceptance"), { recursive: true }), mkdir(path.join(repository, "src"), { recursive: true }), mkdir(task, { recursive: true })]);
  await Promise.all([writeFile(path.join(repository, "project_context", "context.toml"), "schema_version = 4\n"), writeFile(path.join(repository, "src", "value.txt"), "good\n"), writeFile(path.join(repository, "tests", "acceptance", "command.mjs"), `process.stdout.write("command-ok\\n");\n`), writeFile(path.join(repository, "tests", "acceptance", "oracle.mjs"), settings.oracle ?? dynamicOracle())]);
  const data = baseContractData(); if (settings.mutate) settings.mutate(data);
  await Promise.all([writeFile(path.join(task, "product-architecture-source.yaml"), `${JSON.stringify(data.product, null, 2)}\n`), writeFile(path.join(task, "technical-realization-plan.yaml"), `${JSON.stringify(data.plan, null, 2)}\n`), writeFile(path.join(task, "acceptance-checklist.yaml"), `${JSON.stringify(data.checklist, null, 2)}\n`)]);
  if (settings.prepare) await settings.prepare(repository, task);
  await exec("git", ["init", "--quiet"], { cwd: repository }); await exec("git", ["config", "user.email", "external-audit@example.invalid"], { cwd: repository }); await exec("git", ["config", "user.name", "External Audit"], { cwd: repository }); await exec("git", ["add", "-A"], { cwd: repository }); await exec("git", ["commit", "--quiet", "-m", "external audit fixture"], { cwd: repository });
  await grantCandidateTree(repository);
  return task;
}

function attackHandlers() {
  const handlers = new Map();
  handlers.set("v2_source_rejected", async (row, options) => withRuntime(row, options, { mutate: (data) => { data.product.schema_version = "product-source-v2"; } }, async (runtime) => compileOutcome(runtime, row)));
  handlers.set("constant_success_missing_implementation", async (row, options) => withRuntime(row, options, { oracle: staticOracle("good"), prepare: (repository) => rm(path.join(repository, "src", "value.txt")) }, async (runtime) => finalOutcome(runtime, row)));
  handlers.set("oracle_self_signed_passed", async (row, options) => { const value = observation("good"); value.observations.works.passed = true; return withRuntime(row, options, { oracle: `export async function observe(){return ${JSON.stringify(value)};}\n` }, async (runtime) => finalOutcome(runtime, row)); });
  handlers.set("command_target_drift", async (row, options) => withRuntime(row, options, {}, async (runtime) => { const compiled = await runtime.cli("compile"); if (compiled.status !== 0) return commandError(compiled); await writeFile(runtime.path("tests/acceptance/command.mjs"), `process.stdout.write("changed\\n");\n`); return finalOnly(runtime, row); }));
  handlers.set("host_authority_survives_pointer_deletion", async (row, options) => withRuntime(row, options, {}, async (runtime) => { const compiled = await runtime.cli("compile"); if (compiled.status !== 0) return commandError(compiled); await Promise.all([rm(runtime.path(".codex/ty-context-active-long-task.json"), { force: true }), rm(runtime.path(".git/ty-context-active-long-task.json"), { force: true })]); return finalOnly(runtime, row); }));
  handlers.set("forged_final_result_rejected", async (row, options) => withRuntime(row, options, {}, async (runtime) => { const compiled = await runtime.cli("compile"); if (compiled.status !== 0) return commandError(compiled); await runtime.cli("final-gate"); const file = runtime.taskPath("final-result.json"); const envelope = JSON.parse(await readFile(file, "utf8")); envelope.payload.workflow_status = envelope.payload.workflow_status === "accepted" ? "needs_work" : "accepted"; await writeFile(file, `${JSON.stringify(envelope, null, 2)}\n`); const stopped = await runtime.hook("Stop", { stop_hook_active: true, last_assistant_message: "done" }); const reason = String(stopped.reason ?? ""); return { status: stopped.decision === "block" ? "blocked" : "accepted", code: reason.includes(row.expected_code) ? row.expected_code : reason.split(":", 1)[0] || "ok", evidence: JSON.stringify(stopped) }; }));
  handlers.set("no_active_hook_noop", async (row, options) => withRuntime(row, options, {}, async (runtime) => { const result = await runtime.hook("Stop", { last_assistant_message: "ordinary answer" }); return { status: Object.keys(result).length === 0 ? "noop" : "blocked", code: Object.keys(result).length === 0 ? "ok" : "managed_stop_block", evidence: JSON.stringify(result) }; }));
  handlers.set("happy_path", async (row, options) => withRuntime(row, options, {}, async (runtime) => { const compiled = await runtime.cli("compile"); if (compiled.status !== 0) return commandError(compiled); const final = await runtime.cli("final-gate"); const payload = await finalPayload(runtime); const stopped = await runtime.hook("Stop", { stop_hook_active: true, last_assistant_message: "done" }); const resumed = await runtime.hook("SessionStart", { source: "resume" }); const flip = Object.values(payload.counterfactual_results ?? {}).some((item) => item.assertion_flips?.some((entry) => entry.real === true && entry.counterfactual === false)); const accepted = final.status === 0 && payload.workflow_status === "accepted" && flip && Object.keys(stopped).length === 0 && Object.keys(resumed).length === 0; return { status: accepted ? "accepted" : "needs_work", code: accepted ? "ok" : "happy_path_failed", evidence: JSON.stringify({ payload, stopped, resumed }) }; }));
  return handlers;
}

async function withRuntime(row, options, settings, action) { const runtime = await createAuditRuntime(row, options, settings); try { return await action(runtime); } finally { await runtime.cleanup(); } }
async function compileOutcome(runtime, row) { const result = await runtime.cli("compile"); const text = `${result.stdout}\n${result.stderr}`; return { status: result.status === 0 ? "accepted" : "compile_rejected", code: text.includes(row.expected_code) ? row.expected_code : safeCode(text), evidence: text }; }
async function finalOutcome(runtime, row) { const compiled = await runtime.cli("compile"); if (compiled.status !== 0) return commandError(compiled); return finalOnly(runtime, row); }
async function finalOnly(runtime, row) { const command = await runtime.cli("final-gate"); const payload = await finalPayload(runtime); const codes = collectCodes(payload); return { status: payload.workflow_status === "externally_blocked" ? "blocked" : payload.workflow_status, code: codes.has(row.expected_code) ? row.expected_code : payload.workflow_status === "accepted" ? "ok" : [...codes][0] ?? safeCode(`${command.stdout}\n${command.stderr}`), evidence: JSON.stringify(payload) }; }
async function finalPayload(runtime) { return JSON.parse(await readFile(runtime.taskPath("final-result.json"), "utf8")).payload; }
function commandError(result) { const text = `${result.stdout}\n${result.stderr}`; return { status: "compile_rejected", code: safeCode(text), evidence: text }; }
function collectCodes(value, result = new Set()) { if (Array.isArray(value)) value.forEach((item) => collectCodes(item, result)); else if (value && typeof value === "object") for (const [key, item] of Object.entries(value)) { if ((key === "code" || key === "category") && typeof item === "string") result.add(item); if (key === "finding_codes" && Array.isArray(item)) item.filter((entry) => typeof entry === "string").forEach((entry) => result.add(entry)); collectCodes(item, result); } return result; }
function dynamicOracle() { return `import {readFile} from "node:fs/promises";import path from "node:path";export async function observe(input){const value=await readFile(path.join(input.snapshot_root,"src/value.txt"),"utf8").then(item=>item.trim(),()=>null);return {schema_version:"ty-context-observation-v2",observations:{works:{kind:"runtime_behavior",actual:{binding_id:"IB-002",capability:"value.read",value},artifact_refs:[]},forbidden:{kind:"scalar",actual:value,artifact_refs:[]}}};}\n`; }
function staticOracle(value) { return `export async function observe(){return ${JSON.stringify(observation(value))};}\n`; }
function observation(value) { return { schema_version: "ty-context-observation-v2", observations: { works: { kind: "runtime_behavior", actual: { binding_id: "IB-002", capability: "value.read", value }, artifact_refs: [] }, forbidden: { kind: "scalar", actual: value, artifact_refs: [] } } }; }
