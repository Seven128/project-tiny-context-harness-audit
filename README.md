# Project Tiny Context Harness External Audit

This repository publishes the independent `project-tiny-context-harness-audit` package. It installs an exact candidate tarball by SHA-256, drives the real managed Host/Hook boundary, executes its own black-box attack fixtures and six real lockfile consumers, and emits an Ed25519-signed `external-audit-result-v1`.

The audit runner does not import candidate test fixtures or candidate runner code. Its expected outcomes, fixtures, package release, signing key ID, and release commit are pinned independently by the main repository.

## Local release audit

Run inside a Linux root container with bubblewrap, current Host binaries, the Host release signing key, and the dedicated external-audit signing key available as files:

```text
node src/cli.mjs \
  --candidate /artifacts/project-tiny-context-harness-0.4.0.tgz \
  --candidate-sha256 <sha256> \
  --audit-integrity <sha512-sri> \
  --signing-key /secrets/external-audit-private.pem \
  --signing-key-id <public-key-id> \
  --result /artifacts/external-audit-result.json
```

`npm run self-test` validates the immutable expected-outcome surface without a candidate.

The protected `audit-candidate` workflow also binds the downloaded tarball to an exact main-repository commit by rebuilding and hashing that commit. Linux and Windows run in separate fresh jobs with per-job Host and provisional result keys. A later signer job, which never executes candidate code, accepts only the complete passing 8-attack/6-consumer payload and applies the durable audit signature. The dedicated GitHub App then posts `external-long-task-audit` for that exact candidate commit.

For offline signer verification, the installed package supports:

```text
ty-context-external-audit \
  --resign-result <provisional-full-result.json> \
  --candidate-sha256 <sha256> \
  --audit-integrity <sha512-sri> \
  --signing-key <private-key.pem> \
  --signing-key-id <public-key-id> \
  --result <signed-result.json>
```

Resigning rejects diagnostic scope, a changed candidate hash, any missing/extra/reordered case, any expected/actual mismatch, or any non-passing case.

## Trust boundary

- Candidate CLI calls come only from per-case package-manager installations.
- Every attack and consumer uses a fresh Git repository.
- The audit result signature covers the exact candidate hash, audit package integrity, platform, every case result, and the overall verdict.
- Candidate pull requests cannot modify this repository, its release artifact, or its signing secret.
- Candidate execution jobs receive only disposable Host/provisional keys; the durable audit signing key exists only in the isolated signer job.
