import tl = require('azure-pipelines-task-lib');
import { CodeAnalysisScanner, ScannerConfig } from './scanner';

export const VALID_SCANS = ['sast', 'sca', 'secret', 'iac', 'ml', 'api-discovery', 'sbom'];

/** Normalise the scanType input (comma/space separated, case-insensitive) into a set of tokens. */
export function parseScanTypes(raw: string): Set<string> {
  const selected = new Set<string>();
  const tokens = raw.toLowerCase().split(/[\s,]+/).filter(Boolean);
  for (const t of tokens) {
    switch (t) {
      case 'sast':
        selected.add('sast');
        break;
      case 'sca':
        selected.add('sca');
        break;
      case 'secret':
      case 'secrets':
        selected.add('secret');
        break;
      case 'iac':
        selected.add('iac');
        break;
      case 'ml':
      case 'ml-scan':
      case 'mlscan':
        selected.add('ml');
        break;
      case 'api':
      case 'api-discovery':
        selected.add('api-discovery');
        break;
      case 'sbom':
        selected.add('sbom');
        break;
      default:
        console.log(`WARNING: unknown scan type '${t}' (valid: ${VALID_SCANS.join(', ')})`);
    }
  }
  return selected;
}

export async function run(): Promise<void> {
  try {
    const endpoint = tl.getInput('accuknoxEndpoint', true) as string;
    const token = tl.getInput('accuknoxToken', true) as string;
    const label = tl.getInput('accuknoxLabel', true) as string;

    const rawScanType = tl.getInput('scanType', true) as string;
    const selected = parseScanTypes(rawScanType);
    if (selected.size === 0) {
      tl.setResult(
        tl.TaskResult.Failed,
        `scanType did not match any known scan. Provide one or more of: ${VALID_SCANS.join(', ')}.`
      );
      return;
    }

    const softFail = tl.getBoolInput('softFail', false);
    const cfg: ScannerConfig = {
      endpoint,
      token,
      label,
      version: tl.getInput('scannerVersion', false) || 'v0.14.7-rc.3',
      softFail,
    };

    const scanner = new CodeAnalysisScanner(cfg);
    await scanner.setup();
    await scanner.installTools(selected);

    // Run each selected scan; collect the worst exit code and any failures.
    const failures: string[] = [];
    let worstExit = 0;
    const record = (name: string, code: number) => {
      if (code !== 0) {
        worstExit = code;
        failures.push(name);
      }
    };

    if (selected.has('sast')) {
      record(
        'sast',
        await scanner.runSast({
          command: tl.getInput('sastCommand', false) || '.',
          severity: tl.getInput('sastSeverity', false) || '',
        })
      );
    }

    if (selected.has('sca')) {
      record(
        'sca',
        await scanner.runSca({
          command: tl.getInput('scaCommand', false) || 'fs .',
          severity: tl.getInput('scaSeverity', false) || '',
        })
      );
    }

    if (selected.has('secret')) {
      record(
        'secret',
        await scanner.runSecret({
          command: tl.getInput('secretCommand', false) || 'git file://.',
          additionalArguments: tl.getInput('secretAdditionalArguments', false) || '',
        })
      );
    }

    if (selected.has('iac')) {
      record(
        'iac',
        await scanner.runIac({
          command: tl.getInput('iacCommand', false) || '',
          directory: tl.getInput('iacDirectory', false) || '.',
          file: tl.getInput('iacFile', false) || '',
          framework: tl.getInput('iacFramework', false) || '',
          compact: tl.getBoolInput('iacCompact', false),
          quiet: tl.getBoolInput('iacQuiet', false),
        })
      );
    }

    if (selected.has('ml')) {
      record(
        'ml',
        await scanner.runMl({
          command: tl.getInput('mlCommand', false) || 'scan -p . -r json',
          modelName: tl.getInput('mlModelName', false) || '',
          sourceType: tl.getInput('mlSourceType', false) || 'azure',
        })
      );
    }

    if (selected.has('api-discovery')) {
      record(
        'api-discovery',
        await scanner.runApi({
          command: tl.getInput('apiCommand', false) || '-path . -output results.json',
        })
      );
    }

    if (selected.has('sbom')) {
      record(
        'sbom',
        await scanner.runSbom({
          scanType: tl.getInput('sbomScanType', false) || 'filesystem',
          imageRef: tl.getInput('sbomImageRef', false) || '',
          scanPath: tl.getInput('sbomScanPath', false) || '.',
          command: tl.getInput('sbomCommand', false) || '',
          severity: tl.getInput('sbomSeverity', false) || '',
          projectName: tl.getInput('sbomProjectName', false) || '',
        })
      );
    }

    // -------------------- HANDLE RESULT --------------------
    if (worstExit !== 0) {
      const msg = `The following scan(s) reported findings or errors: ${failures.join(', ')}.`;
      if (softFail) {
        console.log(`${msg} Soft fail is enabled, continuing...`);
        tl.setResult(tl.TaskResult.Succeeded, `${msg} Soft fail enabled.`);
      } else {
        tl.setResult(tl.TaskResult.Failed, `${msg} Soft fail is disabled, failing the task.`);
      }
    } else {
      console.log('All selected scans completed successfully.');
      tl.setResult(tl.TaskResult.Succeeded, 'All selected scans completed successfully.');
    }
  } catch (err: any) {
    tl.setResult(tl.TaskResult.Failed, err.message);
  }
}

// Only auto-run when invoked directly by the Azure DevOps agent (not when imported by tests).
if (require.main === module) {
  run();
}
