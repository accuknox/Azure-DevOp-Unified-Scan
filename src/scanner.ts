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
    const dest = path.join(os.tmpdir(), 'accuknox-aspm-scanner');
    const url = `${SCANNER_BASE_URL}/${this.cfg.version}/accuknox-aspm-scanner`;
    console.log(`Downloading AccuKnox ASPM Scanner (${this.cfg.version})...`);
    await this.download(url, dest);
    fs.chmodSync(dest, 0o755);
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
    const args = ['scan', '--keep-results', ...this.softFailArg, 'sast', '--command', i.command];
    if (this.repoUrl) args.push('--repo-url', this.repoUrl);
    if (this.commitSha) args.push('--commit-sha', this.commitSha);
    args.push('--pipeline-id', this.pipelineId, '--job-url', this.jobUrl, '--container-mode');
    if (i.severity.trim()) args.push('--severity', i.severity.trim());
    return this.exec(args);
  }

  async runSca(i: ScaInputs): Promise<number> {
    console.log('Starting AccuKnox SCA scan...');
    const args = ['scan', ...this.softFailArg, 'sca', '--command', i.command, '--container-mode'];
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
    const args = ['scan', '--keep-results', ...this.softFailArg, 'secret', '--command', command, '--container-mode'];
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
    const args = ['scan', ...this.softFailArg, 'iac', '--command', cmdArgs, '--container-mode'];
    if (this.repoUrl) args.push('--repo-url', this.repoUrl);
    if (this.commitRef) args.push('--repo-branch', this.commitRef);
    return this.exec(args);
  }

  async runMl(i: MlInputs): Promise<number> {
    console.log('Starting AccuKnox ML Static scan...');
    const args = ['scan', ...this.softFailArg, 'ml-scan', '--command', i.command, '--container-mode'];
    if (this.repoUrl) args.push('--repo-url', this.repoUrl);
    if (this.commitRef) args.push('--commit-ref', this.commitRef);
    if (i.modelName.trim()) args.push('--model-name', i.modelName.trim());
    if (i.sourceType.trim()) args.push('--source-type', i.sourceType.trim());
    return this.exec(args);
  }

  async runApi(i: ApiInputs): Promise<number> {
    console.log('Starting AccuKnox API Discovery scan...');
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
      '--container-mode',
    ];
    const code = await this.exec(args);
    try {
      if (fs.existsSync('results.json')) fs.copyFileSync('results.json', 'results-sbom.json');
    } catch {
      /* best effort */
    }
    return code;
  }
}
