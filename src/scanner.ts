import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as https from 'https';
import { spawn } from 'child_process';

const SCANNER_BASE_URL = 'https://github.com/accuknox/aspm-scanner-cli/releases/download';

export interface ScannerConfig {
  endpoint: string;
  token: string;
  label: string;
  version: string;
  softFail: boolean;
}

export interface SastInputs {
  command: string;
  severity: string;
  aiAnalysis: boolean;
  aiScanSeverity: string;
  codeassureConfig: string;
}

export interface ScaInputs {
  command: string;
  severity: string;
}

export interface SecretInputs {
  command: string;
  additionalArguments: string;
}

export interface IacInputs {
  command: string;
  directory: string;
  file: string;
  framework: string;
  compact: boolean;
  quiet: boolean;
}

export interface MlInputs {
  command: string;
  modelName: string;
  sourceType: string;
}

export interface ApiInputs {
  command: string;
}

export interface SbomInputs {
  scanType: string;
  imageRef: string;
  scanPath: string;
  command: string;
  severity: string;
  projectName: string;
  enrichLicenses: boolean;
}

/**
 * Azure DevOps predefined variables, mapped to the equivalents the GitHub
 * action passes to the scanner.
 *   BUILD_REPOSITORY_URI    -> repo URL          (GITHUB_REPOSITORY / server URL)
 *   BUILD_SOURCEVERSION     -> full commit SHA   (GITHUB_SHA)
 *   BUILD_SOURCEBRANCHNAME  -> branch name only  (GITHUB_REF#refs/heads/)
 *   BUILD_BUILDID           -> pipeline run id   (GITHUB_RUN_ID)
 */
export class CodeAnalysisScanner {
  private cfg: ScannerConfig;
  private scannerBin: string = '';

  readonly repoUrl: string;
  readonly commitSha: string;
  readonly commitRef: string;
  readonly pipelineId: string;
  readonly jobUrl: string;

  constructor(cfg: ScannerConfig) {
    this.cfg = cfg;
    this.repoUrl = process.env.BUILD_REPOSITORY_URI || '';
    this.commitSha = process.env.BUILD_SOURCEVERSION || '';
    this.commitRef = process.env.BUILD_SOURCEBRANCHNAME || '';
    this.pipelineId = process.env.BUILD_BUILDID || 'unknown';
    this.jobUrl =
      process.env.SYSTEM_COLLECTIONURI &&
      process.env.BUILD_REPOSITORY_NAME &&
      process.env.BUILD_BUILDID &&
      process.env.SYSTEM_JOBID &&
      process.env.SYSTEM_TASKINSTANCEID
        ? `${process.env.SYSTEM_COLLECTIONURI}${process.env.BUILD_REPOSITORY_NAME}/_build/results?buildId=${process.env.BUILD_BUILDID}&view=logs&j=${process.env.SYSTEM_JOBID}&t=${process.env.SYSTEM_TASKINSTANCEID}`
        : 'unknown';
  }

  /** Download the accuknox-aspm-scanner binary once and make it executable. */
  async setup(): Promise<void> {
    const isWindows = process.platform === 'win32';
    const binName = isWindows ? 'accuknox-aspm-scanner.exe' : 'accuknox-aspm-scanner';
    const dest = path.join(os.tmpdir(), binName);
    const url = `${SCANNER_BASE_URL}/${this.cfg.version}/${binName}`;
    console.log(`Downloading AccuKnox ASPM Scanner (${this.cfg.version}, ${process.platform})...`);
    await this.download(url, dest);
    if (!isWindows) fs.chmodSync(dest, 0o755);
    this.scannerBin = dest;
    console.log(`AccuKnox ASPM scanner installed at ${dest}`);
  }

  private download(url: string, dest: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const file = fs.createWriteStream(dest);
      const request = (currentUrl: string, redirects: number) => {
        if (redirects > 10) {
          reject(new Error('Too many redirects while downloading scanner.'));
          return;
        }
        https
          .get(currentUrl, (res) => {
            if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
              res.resume();
              request(res.headers.location, redirects + 1);
              return;
            }
            if (res.statusCode !== 200) {
              res.resume();
              reject(new Error(`Failed to download scanner. HTTP ${res.statusCode}`));
              return;
            }
            res.pipe(file);
            file.on('finish', () => file.close(() => resolve()));
          })
          .on('error', (err) => {
            fs.unlink(dest, () => reject(err));
          });
      };
      request(url, 0);
    });
  }

  /**
   * Scans that run natively, mapped to [tool install --type, path to verify].
   * Verify paths mirror the CLI's ToolManager.TOOL_PATHS. sca and sbom both
   * shell out to Trivy, which ships as the `container` tool.
   * ml and api-discovery are absent: they have no local tool and stay container-mode.
   */
  private static readonly TOOL_FOR_SCAN: Record<string, [string, string]> = {
    sast: ['sast', path.join('sast', 'sast')],
    sca: ['container', 'container'],
    sbom: ['container', 'container'],
    secret: ['secret', 'secret'],
    iac: ['iac', 'iac'],
  };

  /** Where `tool install` places binaries — mirrors the CLI's ToolManager. */
  private get toolsDir(): string {
    if (process.platform === 'win32') {
      return path.join(process.env.USERPROFILE || os.homedir(), 'AppData', 'Local', 'Programs', 'AccuKnox');
    }
    const globalDir = '/usr/share/accuknox-aspm-scanner/tools';
    return fs.existsSync(globalDir) ? globalDir : path.join(os.homedir(), '.local', 'bin', 'accuknox');
  }

  /** Windows tools land as .exe/.bat companions, so check those too. */
  private toolExists(relPath: string): boolean {
    const base = path.join(this.toolsDir, relPath);
    return [base, `${base}.exe`, `${base}.bat`, `${base}.cmd`].some((p) => fs.existsSync(p));
  }

  private async installTool(type: string, verifyRel: string): Promise<void> {
    if (this.toolExists(verifyRel)) {
      console.log(`Scanner tool '${type}' already present, skipping install.`);
      return;
    }
    for (let attempt = 1; attempt <= 3; attempt++) {
      console.log(`Installing scanner tool '${type}' (attempt ${attempt}/3)...`);
      // `tool install` exits 0 even when the download fails, so the exit code
      // proves nothing — verify the binary actually landed instead.
      await this.exec(['tool', 'install', '--type', type]);
      if (this.toolExists(verifyRel)) return;
      console.log(`WARNING: '${type}' not found under ${this.toolsDir} after install; retrying...`);
    }
    throw new Error(
      `Failed to install scanner tool '${type}' after 3 attempts (expected ${path.join(this.toolsDir, verifyRel)}).`
    );
  }

  /** Install local tool binaries for whichever selected scans run natively. */
  async installTools(selected: Set<string>): Promise<void> {
    const needed = new Map<string, string>();
    for (const scan of selected) {
      const entry = CodeAnalysisScanner.TOOL_FOR_SCAN[scan];
      if (entry) needed.set(entry[0], entry[1]);
    }
    for (const [type, verifyRel] of needed) {
      await this.installTool(type, verifyRel);
    }
  }

  /** Common env injected into every scanner invocation. */
  private scanEnv(): NodeJS.ProcessEnv {
    return {
      ...process.env,
      ACCUKNOX_ENDPOINT: this.cfg.endpoint,
      ACCUKNOX_TOKEN: this.cfg.token,
      ACCUKNOX_LABEL: this.cfg.label,
    };
  }

  private get softFailArg(): string[] {
    return this.cfg.softFail ? ['--softfail'] : [];
  }

  /** Run the scanner binary with the given args; resolves the exit code. */
  private exec(args: string[]): Promise<number> {
    if (!this.scannerBin) {
      throw new Error('Scanner not set up. Call setup() first.');
    }
    console.log(`Executing: accuknox-aspm-scanner ${args.join(' ')}`);
    return new Promise((resolve) => {
      const child = spawn(this.scannerBin, args, {
        env: this.scanEnv(),
        stdio: 'inherit',
        shell: false,
      });
      child.on('error', (err) => {
        console.error(`Failed to start scanner: ${err.message}`);
        resolve(1);
      });
      child.on('close', (code) => resolve(code === null ? 1 : code));
    });
  }

  async runSast(i: SastInputs): Promise<number> {
    console.log('Starting AccuKnox SAST scan...');
    if (i.aiAnalysis) {
      try {
        await this.installTool('codeassure', path.join('codeassure', 'codeassure'));
      } catch (e) {
        console.warn(
          `WARNING: could not install codeassure (${e instanceof Error ? e.message : e}). ` +
            'AI-SAST may be skipped; OpenGrep SAST will still run.'
        );
      }
    }
    const args = ['scan', '--keep-results', ...this.softFailArg, 'sast', '--command', i.command];
    if (this.repoUrl) args.push('--repo-url', this.repoUrl);
    if (this.commitSha) args.push('--commit-sha', this.commitSha);
    args.push('--pipeline-id', this.pipelineId, '--job-url', this.jobUrl);
    if (i.severity.trim()) args.push('--severity', i.severity.trim());
    if (i.aiAnalysis) {
      args.push('--ai-analysis');
      if (i.aiScanSeverity.trim()) args.push('--aiscan-severity', i.aiScanSeverity.trim());
      if (i.codeassureConfig.trim()) args.push('--codeassure-config', i.codeassureConfig.trim());
    }
    return this.exec(args);
  }

  async runSca(i: ScaInputs): Promise<number> {
    console.log('Starting AccuKnox SCA scan...');
    const args = ['scan', ...this.softFailArg, 'sca', '--command', i.command];
    if (i.severity.trim()) args.push('--severity', i.severity.trim());
    return this.exec(args);
  }

  async runSecret(i: SecretInputs): Promise<number> {
    console.log('Starting AccuKnox Secret scan...');
    try {
      fs.writeFileSync('./results.jsonl', '');
      fs.chmodSync('./results.jsonl', 0o666);
    } catch (e) {
      console.warn(`Warning: could not pre-create results.jsonl: ${e}`);
    }
    let command = i.command;
    if (i.additionalArguments.trim()) command = `${command} ${i.additionalArguments.trim()}`;
    const args = ['scan', '--keep-results', ...this.softFailArg, 'secret', '--command', command];
    return this.exec(args);
  }

  async runIac(i: IacInputs): Promise<number> {
    console.log('Starting AccuKnox IaC scan...');
    let cmdArgs: string;
    if (i.command.trim()) {
      cmdArgs = i.command.trim();
    } else {
      const parts: string[] = [];
      // --file and --directory are mutually exclusive in the IaC scanner; prefer file when set.
      if (i.file.trim()) {
        parts.push('--file', i.file.trim());
      } else if (i.directory.trim()) {
        parts.push('--directory', i.directory.trim());
      }
      if (i.compact) parts.push('--compact');
      if (i.quiet) parts.push('--quiet');
      if (i.framework.trim()) {
        for (const fw of i.framework.split(',').map((f) => f.trim()).filter(Boolean)) {
          parts.push('--framework', fw);
        }
      }
      cmdArgs = parts.join(' ');
    }
    const args = ['scan', ...this.softFailArg, 'iac', '--command', cmdArgs];
    if (this.repoUrl) args.push('--repo-url', this.repoUrl);
    if (this.commitRef) args.push('--repo-branch', this.commitRef);
    return this.exec(args);
  }

  async runMl(i: MlInputs): Promise<number> {
    console.log('Starting AccuKnox ML Static scan...');
    // Container-only upstream: the CLI has no local ml-scan tool yet, so Docker is still
    // required for this scan. Drop --container-mode once `tool install --type ml-scan` ships.
    const args = ['scan', ...this.softFailArg, 'ml-scan', '--command', i.command, '--container-mode'];
    if (this.repoUrl) args.push('--repo-url', this.repoUrl);
    if (this.commitRef) args.push('--commit-ref', this.commitRef);
    if (i.modelName.trim()) args.push('--model-name', i.modelName.trim());
    if (i.sourceType.trim()) args.push('--source-type', i.sourceType.trim());
    return this.exec(args);
  }

  async runApi(i: ApiInputs): Promise<number> {
    console.log('Starting AccuKnox API Discovery scan...');
    // Container-only upstream: local binary packaging (`tool install --type api-discovery`)
    // is not released yet. Drop --container-mode once it is.
    const args = ['scan', '--keep-results', ...this.softFailArg, 'api-discovery', '--command', i.command, '--container-mode'];
    if (this.repoUrl) args.push('--repo-url', this.repoUrl);
    return this.exec(args);
  }

  async runSbom(i: SbomInputs): Promise<number> {
    console.log('Starting AccuKnox SBOM scan...');
    if (!i.projectName.trim()) {
      throw new Error('sbomProjectName is required when sbom is selected.');
    }
    let cmd: string;
    if (i.command.trim()) {
      cmd = i.command.trim();
    } else {
      const sbomType = i.scanType.trim();
      if (sbomType === 'image') {
        if (!i.imageRef.trim()) {
          throw new Error('sbomImageRef is required when sbomScanType is image.');
        }
        cmd = `image ${i.imageRef.trim()}`;
      } else if (sbomType === 'filesystem' || sbomType === 'path' || sbomType === 'fs') {
        cmd = `filesystem ${i.scanPath.trim()}`;
      } else {
        throw new Error(`Invalid sbomScanType: ${sbomType}. Expected image or filesystem.`);
      }
      if (i.severity.trim()) cmd = `${cmd} --severity ${i.severity.trim()}`;
    }
    const args = [
      'scan',
      ...this.softFailArg,
      '--keep-results',
      '--project-name',
      i.projectName.trim(),
      'container',
      '--command',
      cmd,
      '--generate-sbom',
    ];
    if (i.enrichLicenses) {
      // Filesystem-only CLI flag; image/rootfs logs a warning and skips Syft.
      await this.installTool('syft', 'syft');
      args.push('--enrich-licenses');
    }
    const code = await this.exec(args);
    try {
      if (fs.existsSync('results.json')) fs.copyFileSync('results.json', 'results-sbom.json');
    } catch {
      /* best effort */
    }
    return code;
  }
}
