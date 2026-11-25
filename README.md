# OpenTofu Pre-Commit Hooks

[![Go Tests](https://img.shields.io/github/actions/workflow/status/osinfra-io/tofu-pre-commit-hooks/go-test.yml?style=for-the-badge&logo=go&color=00ADD8&label=Go%20Tests)](https://github.com/osinfra-io/tofu-pre-commit-hooks/actions/workflows/go-test.yml)
[![Dependabot](https://img.shields.io/github/actions/workflow/status/osinfra-io/tofu-pre-commit-hooks/dependabot.yml?style=for-the-badge&logo=github&color=2088FF&label=Dependabot)](https://github.com/osinfra-io/tofu-pre-commit-hooks/actions/workflows/dependabot.yml)

This repository contains [pre-commit](https://pre-commit.com/) hooks for OpenTofu configuration.

## Available Hooks

### tofu-fmt

#### Formats OpenTofu configuration files

Runs `tofu fmt` to rewrite your OpenTofu (`.tf`, `.tofu`, `.tfvars`) files to a canonical format and style. This helps ensure consistency and readability across your infrastructure codebase. It will not modify files in `.terraform/` directories.

### tofu-validate

#### Validates OpenTofu configuration files

Runs `tofu validate` to check your configuration for syntax errors and internal consistency without accessing remote state or provider APIs. By default, the hook first runs `tofu init -backend=false`, which may download providers and modules. It will not validate files in `.terraform/` directories.

### tofu-lint

#### Lints OpenTofu configuration files

Runs `tofu validate -lint=all` in each directory containing OpenTofu configuration. Warnings are advisory and do not fail the hook; initialization or validation errors still fail it. Each warning uses a scan-style `[WARNING]` card with its title, file and line, rule ID, and description. Source excerpts, the experimental notice, and the validation success footer are omitted. This hook requires OpenTofu v1.13 or newer, where built-in linting is experimental and its rules may change.

Unused-local and unused-variable warnings account for shared files: a declaration referenced by any configuration loading the same canonical file is not reported as unused in a partial fixture or shared-file directory. Test assertions in root and default `tests/` test files also count as variable usage in the run's selected module. Unrelated declarations with the same name do not count, and genuinely unused declarations and validation errors remain visible.

This hook performs full validation as well as lint checks. Configure `tofu-lint` instead of both `tofu-validate` and `tofu-lint` to avoid validating every directory twice.

Both hooks check up to four directories concurrently, limited by available CPUs, while keeping initialization serial to protect shared provider caches. Set `args: ["--jobs=1"]` for serial execution, or choose another positive worker count. Initialization remains enabled by default. `args: ["--skip-init"]` skips it only when the caller manages dependency initialization; rerun `tofu init -backend=false` after changing module sources, provider requirements, or lockfiles. Validation alone does not reliably detect stale provider selections.

### tofu-test

#### Runs OpenTofu automated tests

Runs `tofu test` in each directory with `.tftest.hcl` files in the directory itself or its `tests/` subdirectory, excluding hidden directories. Dependencies must already be initialized. OpenTofu tests can create real infrastructure unless configured to use plan-only runs or mocks.

### tofu-scan

#### Checks OpenTofu files against CIS benchmarks

Runs `tofuscan` to check your OpenTofu (`.tofu`) files against CIS benchmark policies using OPA/Rego. Covers [CIS Google Cloud Platform Foundation Benchmark v5.0.0](docs/tofuscan/cis-gcp-v5.0.0.md) and [CIS Google Kubernetes Engine (GKE) Benchmark v1.8.0](docs/tofuscan/cis-gke-v1.8.0.md). It recursively scans `.tofu` files from the repository root, not just changed files, and skips hidden directories including `.terraform/`. The hook is triggered by changes to `.tofu` files; it does not scan `.tf` or `.tfvars` files.

The scan analyzes configuration, not deployed resources. Project-level existence checks combine all scanned files rather than isolating individual projects, so a resource in one project can satisfy a check for another.

---

## Usage

To use these hooks, add them to your `.pre-commit-config.yaml` file. Below are example configurations for the `tofufmt` and `tofuvalidate` hooks.

### Example: `tofu-fmt`

Formats your OpenTofu configuration files to a canonical format and style.

```yaml
- repo: https://github.com/osinfra-io/tofu-pre-commit-hooks
  rev: <release-or-commit-sha>
  hooks:
    - id: tofu-fmt
```

### Example: `tofu-validate`

Validates your OpenTofu configuration files for syntax and internal consistency.

```yaml
- repo: https://github.com/osinfra-io/tofu-pre-commit-hooks
  rev: <release-or-commit-sha>
  hooks:
    - id: tofu-validate
      # Optional: pass additional args to tofu validate
      # args: ["-no-color"]
```

### Example: `tofu-lint`

Runs OpenTofu's experimental built-in lint rules. It requires OpenTofu v1.13 or newer. Warnings are advisory; initialization or validation errors fail the hook. Use `pre-commit run tofu-lint --all-files --verbose` to see warning cards when the hook passes.

```yaml
- repo: https://github.com/osinfra-io/tofu-pre-commit-hooks
  rev: <release-or-commit-sha>
  hooks:
    - id: tofu-lint
```

### Example: `tofu-test`

Runs OpenTofu automated tests defined in `.tftest.hcl` files.

```yaml
- repo: https://github.com/osinfra-io/tofu-pre-commit-hooks
  rev: <release-or-commit-sha>
  hooks:
    - id: tofu-test
      # verbose: true                # show hook output on success
      # Optional: pass additional args to tofu test
      # args: ["-verbose"]                             # show each test run's plan or state
      # args: ["-filter=tests/example.tftest.hcl"]     # equals-form flag
      # args: ["-filter", "tests/example.tftest.hcl"]  # split-form flag
```

`-filter` selects a test file relative to each test module directory. Both equals-form and split-form flags are supported; for split form, include the flag and its value as separate list entries. `-verbose` controls the level of detail `tofu test` itself emits.

Optionally place `.tofu-test.json` in a test module directory to configure that suite:

```json
{
  "workspace": "assembly-main-sandbox",
  "args": ["-var-file=environments/sandbox.tfvars", "-var-file=../foundation/teams/factory.tfvars"]
}
```

Both fields are optional. `workspace` sets `TF_WORKSPACE` only for that suite; without it, the inherited environment is unchanged. The workspace must already exist, and the hook does not initialize dependencies. Arguments are passed directly to `tofu test` without shell expansion, with paths such as `-var-file` relative to the test module directory. Shared hook arguments follow these arguments, so OpenTofu applies its usual precedence (for example, later variable assignments override earlier ones). Invalid or unreadable configuration fails the hook. Tests may create real infrastructure; these settings do not bypass workspace validation.

### Example: `tofu-scan`

Checks OpenTofu files against CIS Google Cloud Foundations Benchmark policies using OPA/Rego. Covers CIS Google Cloud Platform Foundation Benchmark v5.0.0 and CIS Google Kubernetes Engine (GKE) Benchmark v1.8.0.

```yaml
- repo: https://github.com/osinfra-io/tofu-pre-commit-hooks
  rev: <release-or-commit-sha>
  hooks:
    - id: tofu-scan
      # verbose: true     # show hook output on success
      # Optional: pass additional args to tofu scan
      # args: ["--warn-only"]
```

High-severity violations fail the hook. Medium-severity violations are shown as warnings and do not fail it; unclassified severities fail conservatively. `--warn-only` allows commits to pass even when blocking violations are found. Findings are still printed so they remain visible.

#### Skipping violations

To suppress a specific violation, add a skip comment **inside** the resource block:

```hcl
resource "google_compute_firewall" "allow_ssh" {
  # tofu-scan skip: CIS 3.6 - Required for bastion host access
  name    = "allow-ssh-bastion"
  network = "default"
}
```

The format is `# tofu-scan skip: CIS <control> - <reason>`; a non-empty reason is required and shown in the skipped output. Invalid skip comments inside resource blocks fail the scan, including with `--warn-only`. Resource skip comments placed outside a resource block are ignored.

To skip a project-level finding, place a global directive on its own line at the top level of any scanned `.tofu` file:

```hcl
# tofu-scan skip-global: CIS 1.17 - Essential Contacts are managed at the organization level
```

This skips the matching project-level finding across the entire scan, not just one GCP project, and does not skip resource-level findings. A non-empty reason is required; invalid, misplaced, or duplicate global directives fail the scan, including with `--warn-only`. Skipped violations and their reasons remain visible in the output.

Replace `<release-or-commit-sha>` with the desired version or commit hash.

For more details, see the `.pre-commit-hooks.yaml` in this repository.
