const trivyScanner = require('./scanners/trivy');
// const cdxgenScanner = require('./scanners/sbom');
const secretDetectorScanner = require('./scanners/secret-detector');
const path = require('path');
const fs = require('fs');

class NTUSecurityOrchestrator {
  constructor() {
    this.scanners = [];
    this.results = {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      scannerResults: []
    };
  }

  /**
   * Logging utilities for GitLab CI
   */
  log(message, level = 'info') {
    const timestamp = new Date().toISOString();
    const prefix = {
      debug: '🔍 [DEBUG]',
      info: 'ℹ️  [INFO]',
      warning: '⚠️  [WARNING]',
      error: '❌ [ERROR]'
    }[level] || 'ℹ️  [INFO]';

    console.log(`${timestamp} ${prefix} ${message}`);
  }

  debug(message) {
    if (process.env.CI_DEBUG_TRACE || process.env.DEBUG) {
      this.log(message, 'debug');
    }
  }

  info(message) {
    this.log(message, 'info');
  }

  warning(message) {
    this.log(message, 'warning');
  }

  error(message) {
    this.log(message, 'error');
  }

  startGroup(message) {
    console.log(`\n${'='.repeat(60)}`);
    this.info(message);
    console.log('='.repeat(60));
  }

  endGroup() {
    console.log('='.repeat(60) + '\n');
  }

  /**
   * Get the workspace directory (the calling project's directory)
   */
  getWorkspaceDirectory() {
    // GitLab CI sets CI_PROJECT_DIR to the repository directory
    const workspace = process.env.CI_PROJECT_DIR || process.cwd();
    this.info(`🏠 Workspace directory: ${workspace}`);
    return workspace;
  }

  /**
   * Get input from environment variables (GitLab CI pattern)
   */
  getInput(name, defaultValue = '') {
    // Convert input name to environment variable format
    // e.g., 'scan-type' -> 'SCAN_TYPE' or 'INPUT_SCAN_TYPE'
    const envName = `INPUT_${name.toUpperCase().replace(/-/g, '_')}`;
    const simpleName = name.toUpperCase().replace(/-/g, '_');

    return process.env[envName] || process.env[simpleName] || defaultValue;
  }

  /**
   * Register a scanner module
   */
  registerScanner(scanner) {
    this.scanners.push(scanner);
    this.info(`📦 Registered scanner: ${scanner.name}`);
  }

  /**
   * Initialize all scanners
   */
  async initializeScanners() {
    this.startGroup('🔧 NTU Security Scanner Setup');

    for (const scanner of this.scanners) {
      try {
        this.info(`Installing ${scanner.name}...`);
        await scanner.install();
        this.info(`✅ ${scanner.name} installed successfully`);
      } catch (error) {
        this.warning(`Failed to install ${scanner.name}: ${error.message}`);
      }
    }

    this.endGroup();
  }

  /**
   * Run all registered scanners
   */
  async runScans() {
    this.startGroup('🔍 NTU Security Scan');

    const scanType = this.getInput('scan-type', 'fs');
    const scanTarget = this.getInput('scan-target', '.');
    const severity = this.getInput('severity', 'HIGH,CRITICAL');
    const ignoreUnfixed = this.getInput('ignore-unfixed') === 'true';

    // Get the workspace directory and resolve the scan target relative to it
    const workspaceDir = this.getWorkspaceDirectory();
    const resolvedTarget = path.isAbsolute(scanTarget)
      ? scanTarget
      : path.resolve(workspaceDir, scanTarget);

    this.info(`📍 Target: ${scanTarget}`);
    this.info(`🎯 Scan Type: ${scanType}`);
    this.info(`⚠️  Severity Filter: ${severity}`);

    const scanConfig = {
      scanType,
      scanTarget: resolvedTarget,
      severity,
      ignoreUnfixed,
      format: this.getInput('format', 'table'),
      exitCode: this.getInput('exit-code', '1'),
      workspaceDir
    };

    this.info(`Starting scans on target: ${resolvedTarget}`);
    this.info('scanner confirmation', this.scanners.map(s => s.name).join(', '));
    for (const scanner of this.scanners) {
      try {
        this.info(`\n▶️  Running ${scanner.name}...`);
        this.debug(`Scanner config: ${JSON.stringify(scanConfig, null, 2)}`);
        const result = await scanner.scan(scanConfig);
        this.debug(`Scanner result: ${JSON.stringify(result, null, 2)}`);
        this.info(`✅ Scanner completed, checking result...`);
        this.info(`   Result type: ${typeof result}`);
        this.info(`   Result is null: ${result === null}`);
        this.info(`   Result is undefined: ${result === undefined}`);
        if (result) {
          this.aggregateResults(result);
          this.results.scannerResults.push({
            scanner: scanner.name,
            ...result
          });
        }
      } catch (error) {
        this.warning(`${scanner.name} scan failed: ${error.message}`);
      }
    }

    this.endGroup();
  }

  /**
   * Aggregate results from multiple scanners
   */
  aggregateResults(scanResult) {
    this.results.total += scanResult.total || 0;
    this.results.critical += scanResult.critical || 0;
    this.results.high += scanResult.high || 0;
    this.results.medium += scanResult.medium || 0;
    this.results.low += scanResult.low || 0;
  }

  displayResults() {
    this.startGroup('📊 NTU Security Scan Results');

    this.info('='.repeat(50));
    this.info('CONSOLIDATED VULNERABILITY REPORT');
    this.info('='.repeat(50));
    this.info(`   Total Vulnerabilities: ${this.results.total}`);
    this.info(`   🔴 Critical: ${this.results.critical}`);
    this.info(`   🟠 High: ${this.results.high}`);
    this.info(`   🟡 Medium: ${this.results.medium}`);
    this.info(`   🟢 Low: ${this.results.low}`);
    this.info('='.repeat(50));

    // Display per-scanner breakdown
    if (this.results.scannerResults.length > 1) {
      this.info('\n📋 Scanner Breakdown:');
      this.results.scannerResults.forEach(result => {
        this.info(`\n   ${result.scanner}:`);
        this.info(`      Total: ${result.total}`);
        this.info(`      Critical: ${result.critical}, High: ${result.high}`);
      });
    }

    this.endGroup();
  }

  // getTrivySbomResult() {
  //   return this.results.scannerResults.find(
  //     r => r.scanner && r.scanner.toLowerCase().includes('sbom') 
  //     && !r.scanner.toLowerCase().includes('config')
  //   );
  // }

  // getConfigResult() {
  //   return this.results.scannerResults.find(
  //     r => r.scanner && r.scanner.toLowerCase().includes('config')
  //   );
  // }

  // getSecretResult() {
  //   return this.results.scannerResults.find(
  //     r => r.scanner && r.scanner.toLowerCase().includes('secret')
  //   );
  // }

  //  createTableBorder(colWidths) {
  //   const top = '┌' + Object.values(colWidths).map(w => '─'.repeat(w)).join('┬') + '┐';
  //   const middle = '├' + Object.values(colWidths).map(w => '─'.repeat(w)).join('┼') + '┤';
  //   const bottom = '└' + Object.values(colWidths).map(w => '─'.repeat(w)).join('┴') + '┘';
  //   return { top, middle, bottom };
  // }

  // displayVulnerabilityTable(trivySbomResult) {
  //   if (!trivySbomResult || !trivySbomResult.vulnerabilities || trivySbomResult.vulnerabilities.length === 0) {
  //     return;
  //   }

  //   core.info('\n📋 Vulnerability Details:\n');

  //   const colWidths = {
  //     package: 35,
  //     vuln: 22,
  //     severity: 12,
  //     fixed: 18
  //   };

  //   const borders = this.createTableBorder(colWidths);

  //   // Table header
  //   core.info(borders.top);
  //   const header = '│ ' + 'Package'.padEnd(colWidths.package - 2) + ' │ ' +
  //                 'Vulnerability'.padEnd(colWidths.vuln - 2) + ' │ ' +
  //                 'Severity'.padEnd(colWidths.severity - 2) + ' │ ' +
  //                 'Fixed Version'.padEnd(colWidths.fixed - 2) + ' │';
  //   core.info(header);
  //   core.info(borders.middle);

  //   const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  //   const severityEmojis = {
  //     'CRITICAL': '🔴',
  //     'HIGH': '🟠',
  //     'MEDIUM': '🟡',
  //     'LOW': '🟢'
  //   };

  //   severities.forEach(severity => {
  //     const vulnsOfSeverity = trivySbomResult.vulnerabilities.filter(
  //       v => (v.Severity || '').toUpperCase() === severity
  //     );

  //     vulnsOfSeverity.forEach(vuln => {
  //       const pkg = (vuln.PkgName || 'Unknown').substring(0, colWidths.package - 3);
  //       const vulnId = (vuln.VulnerabilityID || 'N/A').substring(0, colWidths.vuln - 3);
  //       const emoji = severityEmojis[severity] || '';
  //       const sev = (emoji + ' ' + severity).substring(0, colWidths.severity - 3);
  //       const fixed = (vuln.FixedVersion || 'N/A').substring(0, colWidths.fixed - 3);

  //       const row = '│ ' + pkg.padEnd(colWidths.package - 2) + ' │ ' +
  //                  vulnId.padEnd(colWidths.vuln - 2) + ' │ ' +
  //                  sev.padEnd(colWidths.severity - 2) + ' │ ' +
  //                  fixed.padEnd(colWidths.fixed - 2) + ' │';
  //       core.info(row);
  //     });
  //   });

  //   core.info(borders.bottom);
  // }

  // displayConfigTable(configResult) {
  //   if (!configResult || !configResult.misconfigurations || configResult.misconfigurations.length === 0) {
  //     return;
  //   }

  //   core.info('\n📋 Misconfiguration Details:\n');

  //   const colWidths = {
  //     file: 30,
  //     issue: 35,
  //     severity: 12,
  //     line: 10
  //   };

  //   const borders = this.createTableBorder(colWidths);

  //   // Table header
  //   core.info(borders.top);
  //   const header = '│ ' + 'File'.padEnd(colWidths.file - 2) + ' │ ' +
  //                 'Issue'.padEnd(colWidths.issue - 2) + ' │ ' +
  //                 'Severity'.padEnd(colWidths.severity - 2) + ' │ ' +
  //                 'Line'.padEnd(colWidths.line - 2) + ' │';
  //   core.info(header);
  //   core.info(borders.middle);

  //   const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  //   const severityEmojis = {
  //     'CRITICAL': '🔴',
  //     'HIGH': '🟠',
  //     'MEDIUM': '🟡',
  //     'LOW': '🟢'
  //   };
  //   severities.forEach(severity => {
  //     const configsOfSeverity = configResult.misconfigurations.filter(
  //       c => (c.Severity || '').toUpperCase() === severity
  //     );

  //     configsOfSeverity.forEach(config => {
  //       const file = (config.File || 'Unknown').substring(0, colWidths.file - 3);
  //       const issue = (config.Issue || config.Title || 'N/A').substring(0, colWidths.issue - 3);
  //       const emoji = severityEmojis[severity] || '';
  //       const sev = (emoji + ' ' + severity).substring(0, colWidths.severity - 3);
  //       const line = (config.Line || 'N/A').toString().substring(0, colWidths.line - 3);

  //       const row = '│ ' + file.padEnd(colWidths.file - 2) + ' │ ' +
  //                  issue.padEnd(colWidths.issue - 2) + ' │ ' +
  //                  sev.padEnd(colWidths.severity - 2) + ' │ ' +
  //                  line.padEnd(colWidths.line - 2) + ' │';
  //       core.info(row);
  //     });
  //   });

  //   core.info(borders.bottom);
  // }

  // displaySecretTable(secretResult) {
  //   if (!secretResult || !secretResult.secrets || secretResult.secrets.length === 0) {
  //     return;
  //   }

  //   core.info('\n📋 Secret Details:\n');

  //   const colWidths = {
  //     file: 70,
  //     line: 10,
  //     matched: 25
  //   };

  //   const borders = this.createTableBorder(colWidths);

  //   // Table header
  //   core.info(borders.top);
  //   const header = '│ ' + 'File'.padEnd(colWidths.file - 2) + ' │ ' +
  //                 'Line'.padEnd(colWidths.line - 2) + ' │ ' +
  //                 'Matched Secret'.padEnd(colWidths.matched - 2) + ' │';
  //   core.info(header);
  //   core.info(borders.middle);

  //   secretResult.secrets.forEach(secret => {
  //     const cleanFile = (secret.File || 'Unknown').replace(/^\/+/, '');
  //     const file = cleanFile.substring(0, colWidths.file - 3);
  //     const line = (secret.StartLine || secret.Line || 'N/A').toString().substring(0, colWidths.line - 3);
  //     const matched = (secret.Match || 'N/A').substring(0, colWidths.matched - 3);

  //     const row = '│ ' + file.padEnd(colWidths.file - 2) + ' │ ' +
  //                line.padEnd(colWidths.line - 2) + ' │ ' +
  //                matched.padEnd(colWidths.matched - 2) + ' │';
  //     core.info(row);
  //   });

  //   core.info(borders.bottom);
  // }

  // /**
  //  * Display consolidated results
  //  */
  // displayResults() {
  //   core.startGroup('📊 NTU Security Scan Results');

  //   core.info('='.repeat(50));
  //   core.info('CONSOLIDATED VULNERABILITY REPORT');
  //   core.info('='.repeat(50));

  //   // Find Trivy scanner result
  //   const trivySbomResult = this.getTrivySbomResult();

  //   if (trivySbomResult) {
  //     core.info(`   Total Vulnerabilities: ${trivySbomResult.total}`);
  //     core.info(`   🔴 Critical: ${trivySbomResult.critical}`);
  //     core.info(`   🟠 High: ${trivySbomResult.high}`);
  //     core.info(`   🟡 Medium: ${trivySbomResult.medium}`);
  //     core.info(`   🟢 Low: ${trivySbomResult.low}`);

  //     // Display vulnerability details in pretty table format
  //     this.displayVulnerabilityTable(trivySbomResult);
  //   } else {
  //     core.info('   ⚠️ No Trivy results found.');
  //   }

  //   core.info('='.repeat(50));

  //   // Find Config scanner result
  //   const configResult = this.getConfigResult();
  //   if (configResult) {
  //     core.info('📋 CONFIG SCANNER RESULTS');
  //     core.info(`   Total Misconfigurations: ${configResult.total}`);
  //     core.info(`   🔴 Critical: ${configResult.critical}`);
  //     core.info(`   🟠 High: ${configResult.high}`);
  //     core.info(`   🟡 Medium: ${configResult.medium}`);
  //     core.info(`   🟢 Low: ${configResult.low}`);
  //     core.info(`   Total Config Files Scanned: ${configResult.totalFiles}`);

  //     this.displayConfigTable(configResult);
  //   } else {
  //     core.info('   ⚠️ No Config scan results found.');
  //   }

  //   core.info('='.repeat(50));

  //   // Find Secret scanner result
  //   const secretResult = this.getSecretResult();
  //   if (secretResult) {
  //     core.info('🔐 SECRET SCANNER RESULTS');
  //     core.info(`   Total Secrets Detected: ${secretResult.total}`);
  //     this.displaySecretTable(secretResult);
  //   } else {
  //     core.info('   ⚠️ No Secret scan results found.');
  //   }

  //   core.info('='.repeat(50));

  //   core.endGroup();
  // }

  /**
   * Set outputs (write to file for GitLab CI)
   */
  setOutputs() {
    // In GitLab CI, we can write outputs to a file or use dotenv artifacts
    const outputData = {
      vulnerabilities_found: this.results.total,
      critical_count: this.results.critical,
      high_count: this.results.high,
      medium_count: this.results.medium,
      low_count: this.results.low,
      scan_result: `Found ${this.results.total} vulnerabilities: ` +
        `${this.results.critical} Critical, ${this.results.high} High, ` +
        `${this.results.medium} Medium, ${this.results.low} Low`
    };

    // Write outputs to dotenv file for GitLab CI
    const dotenvPath = 'scan-outputs.env';
    const dotenvContent = Object.entries(outputData)
      .map(([key, value]) => `${key.toUpperCase()}=${value}`)
      .join('\n');

    try {
      fs.writeFileSync(dotenvPath, dotenvContent);
      this.info(`📝 Outputs written to ${dotenvPath}`);
    } catch (error) {
      this.warning(`Failed to write outputs: ${error.message}`);
    }

    // Also write JSON report
    const jsonPath = 'scan-results.json';
    try {
      fs.writeFileSync(jsonPath, JSON.stringify(this.results, null, 2));
      this.info(`📄 JSON report written to ${jsonPath}`);
    } catch (error) {
      this.warning(`Failed to write JSON report: ${error.message}`);
    }
  }

  /**
   * Post results to Merge Request if applicable
   */
  async postMRComment() {
    const gitlabToken = this.getInput('gitlab-token') || process.env.CI_JOB_TOKEN;
    const gitlabUrl = process.env.CI_API_V4_URL || 'https://gitlab.com/api/v4';
    const projectId = process.env.CI_PROJECT_ID;
    const mrIid = process.env.CI_MERGE_REQUEST_IID;

    if (!gitlabToken || !mrIid) {
      this.debug('Skipping MR comment - not in merge request context or no token available');
      return;
    }

    try {
      const https = require('https');
      const http = require('http');
      const url = require('url');

      const status = (this.results.critical > 0 || this.results.high > 0)
        ? '🔴 VULNERABILITIES DETECTED'
        : '✅ NO CRITICAL ISSUES';
      const emoji = (this.results.critical > 0 || this.results.high > 0) ? '⚠️' : '✅';

      let scannerBreakdown = '';
      if (this.results.scannerResults.length > 1) {
        scannerBreakdown = '\n### Scanner Breakdown\n\n';
        this.results.scannerResults.forEach(result => {
          scannerBreakdown += `**${result.scanner}**: ${result.total} issues ` +
            `(${result.critical} Critical, ${result.high} High)\n`;
        });
      }

      const comment = `## ${emoji} NTU Security Scan Report

**Status:** ${status}

### Consolidated Vulnerability Summary
| Severity | Count |
|----------|-------|
| 🔴 Critical | ${this.results.critical} |
| 🟠 High | ${this.results.high} |
| 🟡 Medium | ${this.results.medium} |
| 🟢 Low | ${this.results.low} |
| **Total** | **${this.results.total}** |
${scannerBreakdown}
${this.results.total > 0 ?
          '⚠️ Please review and address the security vulnerabilities found.' :
          '✨ No security vulnerabilities detected!'}

---
*Powered by NTU Security Scanner*`;

      const apiUrl = `${gitlabUrl}/projects/${projectId}/merge_requests/${mrIid}/notes`;
      const parsedUrl = url.parse(apiUrl);
      const protocol = parsedUrl.protocol === 'https:' ? https : http;

      const postData = JSON.stringify({ body: comment });

      const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port,
        path: parsedUrl.path,
        method: 'POST',
        headers: {
          'PRIVATE-TOKEN': gitlabToken,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData)
        }
      };

      await new Promise((resolve, reject) => {
        const req = protocol.request(options, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            if (res.statusCode >= 200 && res.statusCode < 300) {
              this.info('💬 Posted scan results to MR comment');
              resolve();
            } else {
              reject(new Error(`GitLab API returned ${res.statusCode}: ${data}`));
            }
          });
        });

        req.on('error', reject);
        req.write(postData);
        req.end();
      });

    } catch (error) {
      this.warning(`Failed to post MR comment: ${error.message}`);
    }
  }

  /**
   * Determine if workflow should fail
   */
  shouldFail() {
    const exitCode = this.getInput('exit-code', '1');

    if (exitCode === '0') {
      return false;
    }

    return this.results.total > 0;
  }

  /**
   * Exit with appropriate code
   */
  setFailed(message) {
    this.error(message);
    process.exit(1);
  }
}

async function run() {
  try {
    const orchestrator = new NTUSecurityOrchestrator();

    // Register scanners
    orchestrator.registerScanner(trivyScanner);
    // orchestrator.registerScanner(cdxgenScanner);
    orchestrator.registerScanner(secretDetectorScanner);

    // Initialize all scanners
    await orchestrator.initializeScanners();

    // Run all scans
    await orchestrator.runScans();

    // Display results
    orchestrator.displayResults();

    // Set outputs
    orchestrator.setOutputs();

    // Post MR comment
    await orchestrator.postMRComment();

    // Check if should fail
    if (orchestrator.shouldFail()) {
      orchestrator.setFailed(
        `NTU Security Scanner found ${orchestrator.results.total} vulnerabilities ` +
        `(${orchestrator.results.critical} Critical, ${orchestrator.results.high} High)`
      );
    } else {
      orchestrator.info('✅ Security scan completed successfully');
    }

  } catch (error) {
    console.error(`❌ [ERROR] NTU Security scan failed: ${error.message}`);
    process.exit(1);
  }
}

run();