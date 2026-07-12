import { access, cp, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createAuditRuntime } from "./black-box-runner.mjs";
import { safeCode, sha256 } from "./candidate-installer.mjs";

const auditRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export async function runConsumerLab({ tarball, candidateSha256, ready, expected }) {
  const definitions = consumerDefinitions(); const results = [];
  for (const row of expected) {
    const started = Date.now(); let actual;
    try { const definition = definitions.get(row.id); if (!definition) throw new Error(`external_consumer_missing:${row.id}`); actual = await executeConsumer(row, { tarball, candidateSha256, ready }, definition); }
    catch (error) { actual = { status: "audit_error", code: safeCode(error instanceof Error ? error.message : error), evidence: String(error instanceof Error ? error.message : error), finding_codes: [], manager: null, dependency_key: null, browser_key: null }; }
    if(process.env.TY_CONTEXT_AUDIT_DEBUG==="1")process.stderr.write(`${JSON.stringify({id:row.id,status:actual.status,code:actual.code,finding_codes:actual.finding_codes})}\n`);
    results.push({ id: row.id, expected_status: row.expected_status, actual_status: actual.status, actual_code: actual.code, finding_codes: actual.finding_codes ?? [], passed: actual.status === row.expected_status, duration_ms: Date.now() - started, manager: actual.manager, dependency_key: actual.dependency_key, browser_key: actual.browser_key, evidence_sha256: sha256(actual.evidence) });
  }
  return results;
}

async function executeConsumer(row, options, definition) {
  const fixture = path.join(auditRoot, "fixtures", definition.fixture);
  const runtime = await createAuditRuntime(row, options, {
    oracle: artifactOracle(),
    mutate(data) {
      const spec = data.checklist.verification_specs[0];
      spec.timeout_ms = 180000;
      spec.input_paths = definition.fixture === "npm-workspace" ? ["src/**", "package.json", "package-lock.json", "packages/**", "tests/acceptance/**"] : ["src/**", "package.json", "package-lock.json", "scripts/**", "tests/**", "jest.config.cjs", "playwright.config.mjs", "vitest.config.mjs"];
      spec.artifact_globs = ["product-result.json", "dist/**", ".last-run.json", "**/trace.zip"];
      spec.command_steps = definition.steps;
      if (row.id === "playwright") spec.network_policy = { mode: "loopback", allowed_hosts: [] };
    },
    prepare: (repository) => cp(fixture, repository, { recursive: true })
  });
  try {
    const compiled = await runtime.cli("compile");
    if (compiled.status !== 0) return failure(compiled);
    const final = await runtime.cli("final-gate", [], { timeoutMs: 12 * 60_000 });
    const payload = JSON.parse(await readFile(runtime.taskPath("final-result.json"), "utf8")).payload;
    const contract = JSON.parse(await readFile(runtime.taskPath("compiled-contract.json"), "utf8"));
    const plan = contract.dependency_plan;
    const layerValid = plan.required === true && plan.manager?.name === "npm" && plan.lockfile?.sha256 && payload.dependency_layer_keys?.length === 1;
    const browserValid = row.id === "playwright" ? payload.browser_layer_keys?.length === 1 : payload.browser_layer_keys?.length === 0;
    let extraValid = true;
    if (row.id === "built_artifact") { const built = runtime.taskPath(`runs/${payload.run_id}/artifacts/VS-AC-001/dist/built-value.mjs`); await access(built); extraValid = (await readFile(built, "utf8")).includes("good"); }
    const accepted = final.status === 0 && payload.workflow_status === "accepted" && layerValid && browserValid && extraValid;
    return { status: accepted ? "accepted" : "needs_work", code: accepted ? "ok" : "consumer_contract_failed", finding_codes: [...new Set((payload.findings??[]).flatMap((item)=>[item.code,item.category]).filter(Boolean))].sort(), manager: plan.manager?.name ?? null, dependency_key: payload.dependency_layer_keys?.[0] ?? null, browser_key: payload.browser_layer_keys?.[0] ?? null, evidence: JSON.stringify({ workflow_status: payload.workflow_status, dependency_plan: { required: plan.required, manager: plan.manager?.name, lockfile: plan.lockfile, required_project_binaries: plan.required_project_binaries, playwright_packages: plan.playwright_packages }, dependency_layer_keys: payload.dependency_layer_keys, browser_layer_keys: payload.browser_layer_keys, findings: payload.findings }) };
  } finally { await runtime.cleanup(); }
}

function consumerDefinitions() {
  const step = (id, tool, target, argv = []) => ({ id, tool, target, argv, cwd: ".", timeout_ms: 180000, environment_refs: [], output_artifact_ids: [] });
  return new Map([
    ["npm_dependency_import", { fixture: "real-consumer", steps: [step("CMD-NPM", "package_script", "verify:npm")] }],
    ["npm_workspaces", { fixture: "npm-workspace", steps: [step("CMD-WORKSPACE", "package_script", "verify:workspace")] }],
    ["vitest", { fixture: "real-consumer", steps: [step("CMD-VITEST", "project_binary", "vitest", ["run", "tests/vitest.test.mjs", "--config=vitest.config.mjs", "--configLoader=runner", "--pool=threads", "--fileParallelism=false"]), step("CMD-MARK", "node_script", "scripts/mark-success.mjs")] }],
    ["jest", { fixture: "real-consumer", steps: [step("CMD-JEST", "project_binary", "jest", ["--config=jest.config.cjs", "--runTestsByPath", "tests/jest.test.cjs", "--runInBand", "--no-cache"]), step("CMD-MARK", "node_script", "scripts/mark-success.mjs")] }],
    ["playwright", { fixture: "real-consumer", steps: [step("CMD-PLAYWRIGHT", "playwright_test", "tests/playwright.spec.mjs", ["--config=playwright.config.mjs", "--project=chromium"])] }],
    ["built_artifact", { fixture: "real-consumer", steps: [step("CMD-BUILD", "package_script", "verify:build")] }]
  ]);
}

function artifactOracle() { return `import {readFile} from "node:fs/promises";import path from "node:path";export async function observe(input){const value=await readFile(path.join(input.artifact_root,"product-result.json"),"utf8").then(item=>JSON.parse(item).value,()=>null);return {schema_version:"ty-context-observation-v2",observations:{works:{kind:"runtime_behavior",actual:{binding_id:"IB-002",capability:"value.read",value},artifact_refs:[]},forbidden:{kind:"scalar",actual:value,artifact_refs:[]}}};}\n`; }
function failure(result) { const evidence = `${result.stdout}\n${result.stderr}`; return { status: "compile_rejected", code: safeCode(evidence), finding_codes: [safeCode(evidence)], manager: null, dependency_key: null, browser_key: null, evidence }; }
