# 🛡️ AccuKnox Code Analysis — Azure DevOps Extension

The **AccuKnox Code Analysis** extension is a single, unified Azure DevOps task that runs any combination of AccuKnox ASPM code-analysis scans — **SAST, SCA, Secret, IaC, ML Static Scan, API Discovery and SBOM** — and uploads the results to the **AccuKnox Console** for centralized visibility, risk tracking and remediation.

Instead of wiring up a separate task for every scanner, configure **one task**, pick the scans you need via `scanType`, and shift security left across your entire codebase — **before it reaches production**.

---

## 🎯 Key Features

- ✅ **7 Scanners, One Task** – SAST (optional AI-SAST), SCA, Secret, IaC, ML Static Scan, API Discovery and SBOM (image + filesystem).
- 🧩 **Run Any Combination** – Select one or many scans with a single comma/space separated `scanType` input.
- 🤖 **AI-SAST** – After OpenGrep SAST, optionally run CodeAssure AI analysis (`enableAiSast`) to triage findings.
- ⌨️ **Command Text Per Scan** – Every scanner exposes a `*Command` input mapped directly to the CLI's `--command`.
- 🏗️ **IaC with Frameworks** – Restrict IaC scans to one or more frameworks (e.g. `Kubernetes,Terraform`).
- 📦 **SBOM for Image & Filesystem** – Generate a CycloneDX SBOM from a container image or your source tree. Optional Syft license enrich (`sbomEnrichLicenses`) for filesystem SBOM.
- 🔒 **Shift Left Security** – Integrate all checks directly into your Azure Pipelines.
- 📥 **Seamless AccuKnox Console Integration** – Findings flow automatically to the AccuKnox dashboard.

---

## ⚠️ Prerequisites

- 🖥️ **Any Linux or Windows agent** – SAST, SCA, Secret, IaC and SBOM run the scanner natively, so Microsoft-hosted agents work; no Docker required.
- 🤖 **AI-SAST** – Native CodeAssure install on Linux and Windows. Enable with `enableAiSast` or `ACCUKNOX_ENABLE_AI_SAST=TRUE`. Put the LLM key in `ACCUKNOX_AI_API_KEY` (provider-agnostic) and map it on the task with `env:`. In `codeassure.json` set `"api_key": "$ACCUKNOX_AI_API_KEY"`. Optionally pass the config path as `sastCodeassureConfig`.
- 🐳 **Docker (only for ML Static Scan and API Discovery)** – These two scans still run in container mode, so selecting either one requires an agent with Docker available and network access to pull scanner images.
- 🔐 **AccuKnox Console Access** – Sign in to your AccuKnox tenant.
- 🗝️ **API Token** – Retrieve this from the AccuKnox Console (**Settings → Tokens**).
- 🏷️ **Label Created in Console** – For tagging the uploaded scan reports.
- 🔑 **Pipeline Variables / Secrets** – Store the credentials securely as pipeline variables.

---

## 📌 Installation & Usage

### Step 1: Retrieve AccuKnox Credentials

1. Log in to your AccuKnox Console.
2. Navigate to **Settings → Tokens**, click **Create Token**, and save the value.
3. Create a label under **Dashboard → Labels** to tag scan results.

### Step 2: Add Pipeline Variables

Define the following as pipeline variables (mark the token as secret):

| Variable | Description |
|----------|-------------|
| `ACCUKNOX_TOKEN` | Your AccuKnox API token |
| `ACCUKNOX_ENDPOINT` | The AccuKnox Console URL (e.g. `cspm.demo.accuknox.com`) |
| `ACCUKNOX_LABEL` | Label used to tag and group scan results |
| `ACCUKNOX_ENABLE_AI_SAST` (optional) | Set to `TRUE` to enable AI-SAST (same as `enableAiSast`) |
| `ACCUKNOX_AI_API_KEY` (optional) | Provider-agnostic LLM API key for AI-SAST. Mark as secret and map it on the task with `env:`. `codeassure.json` must use `"api_key": "$ACCUKNOX_AI_API_KEY"` |

### Step 3: Add the Task to Your Pipeline

```yaml
trigger:
- main

pool:
  name: selfhosted

steps:
- task: AccuKnox-Code-Analysis@3
  inputs:
    # Pick any combination of scans
    scanType: 'sast, sca, secret, iac'

    # AccuKnox credentials
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)

    # Common options
    softFail: true
```

> 💡 Only the inputs for the scans listed in `scanType` are used — everything else is ignored, so you can keep your pipeline minimal.

---

## 📝 Examples

### 1. SAST

```yaml
- task: AccuKnox-Code-Analysis@3
  inputs:
    scanType: 'sast'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    sastSeverity: 'HIGH,CRITICAL'
    softFail: true
```

### 1a. SAST in container mode (internal registry)

Does not call GitHub `tool install`. Mirror `public.ecr.aws/k9v9d5v2/accuknox/opengrepjob:0.1.0` into the customer registry first.

```yaml
- task: AccuKnox-Code-Analysis@3
  inputs:
    scanType: 'sast'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    containerMode: true
    scanImage: 'registry.internal/accuknox/opengrepjob:0.1.0'
    enableAiSast: false
    softFail: true
```

### 1b. SAST with AI analysis

Enable with `enableAiSast: true` or `ACCUKNOX_ENABLE_AI_SAST=TRUE`. Store the LLM key in `ACCUKNOX_AI_API_KEY` (any provider). Works on Linux and Windows agents.

```yaml
- task: AccuKnox-Code-Analysis@3
  env:
    ACCUKNOX_ENABLE_AI_SAST: 'TRUE'   # optional if enableAiSast is true
    ACCUKNOX_AI_API_KEY: $(ACCUKNOX_AI_API_KEY)
  inputs:
    scanType: 'sast'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    sastSeverity: 'HIGH,CRITICAL'
    enableAiSast: true
    sastAiScanSeverity: 'HIGH,CRITICAL'
    # sastCodeassureConfig: 'codeassure.json'   # optional
    softFail: true
```

Example `codeassure.json` — the key name is AccuKnox-generic; `provider` / `api_base` pick the actual LLM:

```json
{
  "model": {
    "provider": "openai-compatible",
    "name": "your-model-name",
    "api_base": "https://your-llm-endpoint",
    "api_key": "$ACCUKNOX_AI_API_KEY",
    "tool_calling": true
  }
}
```

### 2. SCA

```yaml
- task: AccuKnox-Code-Analysis@3
  inputs:
    scanType: 'sca'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    scaSeverity: 'HIGH,CRITICAL'
    softFail: true
```

### 3. Secret

```yaml
- task: AccuKnox-Code-Analysis@3
  inputs:
    scanType: 'secret'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    softFail: true
```

### 4. IaC

```yaml
- task: AccuKnox-Code-Analysis@3
  inputs:
    scanType: 'iac'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    softFail: true
```

### 5. ML Static Scan

```yaml
- task: AccuKnox-Code-Analysis@3
  inputs:
    scanType: 'ml'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    softFail: true
```

### 6. API Discovery

```yaml
- task: AccuKnox-Code-Analysis@3
  inputs:
    scanType: 'api-discovery'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    softFail: true
```

### 7. SBOM

> **Prerequisite — Create a Project.** To associate SBOM data with the correct entity, create a **Project** in the AccuKnox Console first (**SBOM → Projects → New Project**). Use **Container** classifier for an image SBOM or **Application** for a filesystem SBOM, and pass the project name as `sbomProjectName`.

```yaml
- task: AccuKnox-Code-Analysis@3
  inputs:
    scanType: 'sbom'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    sbomScanType: 'filesystem'
    sbomScanPath: '.'
    sbomProjectName: 'my-project'   # required for SBOM
    # sbomEnrichLicenses: true        # optional; needs scanner newer than v0.14.9
    softFail: true
```

> For an **image** SBOM, set `sbomScanType: 'image'` and `sbomImageRef: 'myapp:latest'` (build/pull the image earlier in the same job).

### 8. Unified — Multiple Scans in One Task

```yaml
- task: AccuKnox-Code-Analysis@3
  inputs:
    scanType: 'sast, sca, secret, iac, sbom'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    softFail: true
    sastSeverity: 'HIGH,CRITICAL'
    sbomScanType: 'filesystem'
    sbomScanPath: '.'
    sbomProjectName: 'my-project'
```

> Add `ml` and `api-discovery` to `scanType` to include those scans — they run in container mode, so the agent needs Docker.

---

## ⚙️ Configuration Options (Inputs)

### Common

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `scanType` | Scans to run (comma/space separated): `sast`, `sca`, `secret`, `iac`, `ml`, `api-discovery`, `sbom` | Yes | — |
| `accuknoxEndpoint` | URL of the AccuKnox Console to push results | Yes | — |
| `accuknoxToken` | API token for authenticating with AccuKnox SaaS | Yes | — |
| `accuknoxLabel` | Label used in AccuKnox SaaS to organise results | Yes | — |
| `scannerVersion` | Git tag of the `accuknox-aspm-scanner` binary (GitHub). Ignored if `scannerPath` or a bundled CLI is present | No | `v0.15.1` |
| `scannerPath` | Absolute path to a CLI already on the agent. Skips GitHub download | No | `""` |
| `scannerDownloadUrl` | Internal HTTPS URL of the CLI binary. Used when path/bundle are empty | No | `""` |
| `softFail` | Prevent the task from failing on findings (all scans) | No | `true` |
| `containerMode` | Run scanners in Docker (`--container-mode`). Skips GitHub `tool install`. Same as `ACCUKNOX_CONTAINER_MODE=TRUE`. Agent needs Docker. | No | `false` |
| `scanImage` | Sets `SCAN_IMAGE` (internal registry). Example: `registry.internal/accuknox/opengrepjob:0.1.0`. One image per job. | No | `""` (public ECR default) |

### SAST (`sast`)

| Input | Description | Default |
|-------|-------------|---------|
| `sastCommand` | Command text passed to `--command` (target to scan) | `.` |
| `sastSeverity` | Comma-separated severities (`LOW, MEDIUM, HIGH, CRITICAL`) | `HIGH` |
| `enableAiSast` | After OpenGrep SAST, run CodeAssure AI analysis (`--ai-analysis`). Same as `ACCUKNOX_ENABLE_AI_SAST=TRUE` | `false` |
| `sastAiScanSeverity` | OpenGrep impacts sent to CodeAssure (`--aiscan-severity`). Shown when AI-SAST is on | `HIGH,CRITICAL` |
| `sastCodeassureConfig` | Optional path to `codeassure.json` (`--codeassure-config`). Use `"api_key": "$ACCUKNOX_AI_API_KEY"` | `""` |

### SCA (`sca`)

| Input | Description | Default |
|-------|-------------|---------|
| `scaCommand` | Command text passed to `--command` (e.g. `fs .`) | `fs .` |
| `scaSeverity` | Comma-separated severities to fail on | `""` |

### Secret (`secret`)

| Input | Description | Default |
|-------|-------------|---------|
| `secretCommand` | Command text passed to `--command` (e.g. `git file://.` or `filesystem .`) | `git file://.` |
| `secretAdditionalArguments` | Extra arguments appended to the command | `""` |

### IaC (`iac`)

| Input | Description | Default |
|-------|-------------|---------|
| `iacCommand` | Raw command text passed to `--command`. Overrides the structured inputs below | `""` |
| `iacDirectory` | Directory with infrastructure code to scan | `.` |
| `iacFile` | Specific file to scan; cannot be used with `iacDirectory` | `""` |
| `iacFramework` | One or more frameworks (comma-separated), e.g. `Kubernetes,Terraform` | `""` (all) |
| `iacCompact` | Do not display code blocks in output | `true` |
| `iacQuiet` | Display only failed checks | `true` |

### ML Static Scan (`ml`)

| Input | Description | Default |
|-------|-------------|---------|
| `mlCommand` | Command text passed to `--command` (e.g. `scan -p . -r json`) | `scan -p . -r json` |
| `mlModelName` | Custom collector/model identifier | `""` |
| `mlSourceType` | Source type for metadata | `azure` |

### API Discovery (`api-discovery`)

| Input | Description | Default |
|-------|-------------|---------|
| `apiCommand` | Command text passed to `--command` (e.g. `-path . -output results.json`) | `-path . -output results.json` |

### SBOM (`sbom`)

| Input | Description | Default |
|-------|-------------|---------|
| `sbomScanType` | Target type: `image` or `filesystem` | `filesystem` |
| `sbomImageRef` | Image reference (required when `sbomScanType` is `image`) | `""` |
| `sbomScanPath` | Filesystem path (used when `sbomScanType` is `filesystem`) | `.` |
| `sbomCommand` | Raw command text passed to `--command`. Overrides the structured inputs above | `""` |
| `sbomSeverity` | Comma-separated severities | `""` |
| `sbomProjectName` | Project name (AccuKnox entity). **Required** when `sbom` is selected | `""` |
| `sbomEnrichLicenses` | Filesystem SBOM only: after Trivy, run Syft and copy missing SPDX licenses (`--enrich-licenses`). Default off. Needs a scanner newer than `v0.14.9`. | `false` |

---

## 🔍 How It Works

1. **Pipeline runs** – A push/PR triggers the pipeline containing the task.
2. **Scanner setup (once)** – The task validates credentials, parses `scanType`, then resolves the CLI in this order: `scannerPath` on the agent, a binary bundled in the VSIX (`src/bin/`), `scannerDownloadUrl`, or GitHub `scannerVersion`. Use `scannerPath` or the bundled VSIX when the agent cannot reach github.com. Native mode still runs `tool install` (GitHub) unless tools are already on the agent. **Container mode** (`containerMode: true`) skips `tool install` and runs Docker instead; set `scanImage` to an internal-registry copy of the scanner image.
3. **Selected scans run** – Each enabled scan builds its arguments from your `*Command` and scan-specific inputs. With `containerMode`, SAST/SCA/Secret/IaC/SBOM also use `--container-mode`. ML and API Discovery always use Docker:
   - **SAST** → static application security analysis (optional **AI-SAST** via `enableAiSast`)
   - **SCA** → dependency/composition analysis
   - **Secret** → secret detection
   - **IaC** → infrastructure-as-code misconfiguration checks (optionally per framework)
   - **ML** → static ML model analysis
   - **API Discovery** → route/endpoint discovery
   - **SBOM** → CycloneDX bill of materials for an image or filesystem (optional Syft license enrich via `sbomEnrichLicenses`)
4. **Results uploaded to AccuKnox Console** – Using the provided `accuknoxToken` and `accuknoxLabel`.
5. **Review findings** – Available in the AccuKnox Console: **Dashboard → Issues → Findings**, filtered by scan type.
6. **Pipeline decision** – If `softFail` is `false`, the task fails when any selected scan reports findings.

---

## 📖 Support & Documentation

- 📚 **Read More:** [AccuKnox Docs](https://help.accuknox.com/)
- 📧 **Contact Support:** support@accuknox.com

---

**🔐 Shift Left with AccuKnox – Secure Your Code from Commit to Cloud! ☁️🛡️**
