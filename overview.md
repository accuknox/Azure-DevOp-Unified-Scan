# AccuKnox Code Analysis

Unified AccuKnox ASPM scanner for Azure DevOps. Run any combination of **SAST, SCA, Secret, IaC, ML Static Scan, API Discovery and SBOM** scans in a **single task** and upload the findings to the **AccuKnox Console** for centralized visibility, risk tracking and remediation.

Instead of adding a separate task for every scanner, configure one task, pick the scans you need via **Scan Types**, and shift security left across your entire codebase.

## Features

- **7 scanners, one task** – SAST (optional AI-SAST), SCA, Secret, IaC, ML Static Scan, API Discovery and SBOM (image + filesystem).
- **Run any combination** – Select one or many scans from the multi-select **Scan Types** input.
- **Per-scan command text** – Every scanner exposes a `*Command` input mapped directly to the CLI's `--command`.
- **IaC with frameworks** – Restrict IaC scans to one or more frameworks (e.g. `Kubernetes,Terraform`).
- **SBOM for image & filesystem** – Generate a CycloneDX SBOM from a container image or your source tree.
- **Soft fail** – Optionally keep the pipeline green even when findings are detected.

## Prerequisites

- Any **Linux or Windows** Azure DevOps agent, hosted or self-hosted — SAST, SCA, Secret, IaC and SBOM run natively by default.
- **Container mode** (`containerMode: true` or `ACCUKNOX_CONTAINER_MODE=TRUE`) runs those scans in Docker instead, skips GitHub tool downloads, and uses `scanImage` / `SCAN_IMAGE` from an internal registry when public ECR is blocked. The agent needs Docker and must be able to pull (or already have) that image.
- **AI-SAST** runs on **Linux or Windows**. Enable with `enableAiSast` or `ACCUKNOX_ENABLE_AI_SAST=TRUE`. Map `ACCUKNOX_AI_API_KEY` on the task with `env:`, and set `codeassure.json` `api_key` to `$ACCUKNOX_AI_API_KEY`.
- **Docker** is also required for **ML Static Scan** and **API Discovery**.
- An **AccuKnox Console** tenant, an **API token**, and a **label** to tag the uploaded results.

## Inputs

| Name | Description | Required | Default |
|------|-------------|----------|---------|
| `scanType` | Scans to run: `sast`, `sca`, `secret`, `iac`, `ml`, `api-discovery`, `sbom` | Yes | — |
| `accuknoxEndpoint` | AccuKnox Console URL to push results to | Yes | — |
| `accuknoxToken` | AccuKnox API token | Yes | — |
| `accuknoxLabel` | Label for associating scan results | Yes | — |
| `scannerVersion` | Git tag of the `accuknox-aspm-scanner` binary (GitHub). Ignored if `scannerPath` or a bundled CLI is present | No | `v0.15.1` |
| `scannerPath` | Absolute path to a CLI already on the agent. Skips GitHub | No | `""` |
| `scannerDownloadUrl` | Internal HTTPS URL of the CLI. Used when path/bundle are empty | No | `""` |
| `softFail` | Do not fail the task on findings | No | `true` |
| `containerMode` | Docker `--container-mode`; skips GitHub `tool install` | No | `false` |
| `scanImage` | `SCAN_IMAGE` (internal registry), e.g. `registry.internal/accuknox/opengrepjob:0.1.0` | No | `""` |

Each scan also exposes its own optional inputs (see the README for the full table).

## Examples

All examples assume the credentials are defined as pipeline variables: `ACCUKNOX_ENDPOINT`, `ACCUKNOX_TOKEN`, `ACCUKNOX_LABEL`.

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

### 1a. SAST in container mode (internal registry, no GitHub)

Mirror `public.ecr.aws/k9v9d5v2/accuknox/opengrepjob:0.1.0` into the customer registry, then:

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

The agent needs Docker. Pre-pull or `docker load` the image so the job never reaches public ECR or GitHub.

### 1b. SAST with AI analysis

```yaml
- task: AccuKnox-Code-Analysis@3
  env:
    ACCUKNOX_ENABLE_AI_SAST: 'TRUE'
    ACCUKNOX_AI_API_KEY: $(ACCUKNOX_AI_API_KEY)
  inputs:
    scanType: 'sast'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    sastSeverity: 'HIGH,CRITICAL'
    enableAiSast: true
    sastAiScanSeverity: 'HIGH,CRITICAL'
    softFail: true
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

> **Prerequisite — Create a Project** in the AccuKnox Console first (**SBOM → Projects → New Project**). Use the **Container** classifier for an image SBOM or **Application** for a filesystem SBOM, and pass the project name as `sbomProjectName`.

Filesystem SBOM:

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

Image SBOM (build/pull the image earlier in the same job):

```yaml
- task: AccuKnox-Code-Analysis@3
  inputs:
    scanType: 'sbom'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    sbomScanType: 'image'
    sbomImageRef: 'myapp:latest'
    sbomProjectName: 'my-project'
    softFail: true
```

### 8. Unified — multiple scans in one task

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

Review findings in the AccuKnox Console under **Dashboard → Issues → Findings**, filtered by scan type.
