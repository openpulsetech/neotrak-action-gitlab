/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 16:
/***/ ((module) => {

"use strict";
module.exports = require("url");

/***/ }),

/***/ 317:
/***/ ((module) => {

"use strict";
module.exports = require("child_process");

/***/ }),

/***/ 513:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

const fs = __webpack_require__(896);
const os = __webpack_require__(857);
const path = __webpack_require__(928);
const { execSync } = __webpack_require__(317);

// Trivy scanner configuration
const TRIVY_VERSION = 'v0.48.0';
const SCANNER_BINARY = 'ntu-scanner-trivy';

class TrivyScanner {
  constructor() {
    this.name = 'Trivy Vulnerability Scanner';
    this.binaryPath = null;
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

  /**
   * Install Trivy scanner
   */
  async install() {
    try {
      this.setupGitLabEnvironment();
      
      const platform = os.platform();
      const arch = os.arch() === 'x64' ? 'amd64' : os.arch();
      
      let downloadUrl;
      
      if (platform === 'linux') {
        downloadUrl = `https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION.replace('v', '')}_Linux-${arch === 'amd64' ? '64bit' : 'ARM64'}.tar.gz`;
      } else if (platform === 'darwin') {
        downloadUrl = `https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION.replace('v', '')}_macOS-${arch === 'amd64' ? '64bit' : 'ARM64'}.tar.gz`;
      } else if (platform === 'win32') {
        downloadUrl = `https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION.replace('v', '')}_windows-${arch === 'amd64' ? '64bit' : 'ARM64'}.zip`;
      }
      
      this.debug(`Downloading from: ${downloadUrl}`);
      
      // Create temp directory
      const tempDir = path.join(os.tmpdir(), `trivy-install-${Date.now()}`);
      fs.mkdirSync(tempDir, { recursive: true });
      
      const downloadPath = path.join(tempDir, 'trivy-archive');
      
      // Download using curl (available in GitLab CI runners)
      this.info('📥 Downloading Trivy scanner...');
      execSync(`curl -L -o "${downloadPath}" "${downloadUrl}"`, { stdio: 'inherit' });
      
      // Extract
      this.info('📦 Extracting archive...');
      const extractDir = path.join(tempDir, 'extracted');
      fs.mkdirSync(extractDir, { recursive: true });
      
      if (platform === 'win32') {
        execSync(`unzip -q "${downloadPath}" -d "${extractDir}"`, { stdio: 'inherit' });
      } else {
        execSync(`tar -xzf "${downloadPath}" -C "${extractDir}"`, { stdio: 'inherit' });
      }
      
      // Rename binary to hide Trivy branding
      const originalBinary = platform === 'win32' ? 'trivy.exe' : 'trivy';
      const newBinary = platform === 'win32' ? `${SCANNER_BINARY}.exe` : SCANNER_BINARY;
      
      const trivyPath = path.join(extractDir, originalBinary);
      const cacheDir = process.env.SCANNER_CACHE_DIR || path.join(os.homedir(), '.cache', 'ntu-scanner');
      fs.mkdirSync(cacheDir, { recursive: true });
      
      const scannerPath = path.join(cacheDir, newBinary);
      
      if (fs.existsSync(trivyPath)) {
        fs.copyFileSync(trivyPath, scannerPath);
      } else {
        throw new Error(`Trivy binary not found at ${trivyPath}`);
      }
      
      // Make executable on Unix systems
      if (platform !== 'win32') {
        fs.chmodSync(scannerPath, '755');
      }
      
      this.binaryPath = scannerPath;
      
      // Add to PATH for this process
      process.env.PATH = `${cacheDir}${path.delimiter}${process.env.PATH}`;
      
      // Cleanup temp directory
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch (cleanupError) {
        this.debug(`Failed to cleanup temp directory: ${cleanupError.message}`);
      }
      
      this.info(`✅ Trivy scanner installed at: ${scannerPath}`);
      
      return this.binaryPath;
      
    } catch (error) {
      throw new Error(`Failed to install Trivy: ${error.message}`);
    }
  }

  /**
   * Set up GitLab CI environment
   */
  setupGitLabEnvironment() {
    // Set up environment variables for GitLab CI
    if (!process.env.CI_PROJECT_DIR) {
      process.env.CI_PROJECT_DIR = process.cwd();
    }
    
    if (!process.env.CI_BUILDS_DIR) {
      process.env.CI_BUILDS_DIR = process.cwd();
    }
    
    const cacheDir = process.env.SCANNER_CACHE_DIR || path.join(os.homedir(), '.cache', 'ntu-scanner');
    
    // Ensure cache directory exists
    if (!fs.existsSync(cacheDir)) {
      fs.mkdirSync(cacheDir, { recursive: true });
    }
    
    this.debug(`GitLab environment setup: CI_PROJECT_DIR=${process.env.CI_PROJECT_DIR}`);
    this.debug(`GitLab environment setup: SCANNER_CACHE_DIR=${cacheDir}`);
  }

  /**
   * Run Trivy scan
   */
  async scan(config) {
    try {
      const {
        scanType,
        scanTarget,
        severity,
        ignoreUnfixed
      } = config;
      
      // Validate scan target exists
      if (!fs.existsSync(scanTarget)) {
        throw new Error(`Scan target does not exist: ${scanTarget}`);
      }
      
      // Convert severity to uppercase (Trivy expects uppercase)
      const severityUpper = severity.toUpperCase();
      
      this.info(`🔍 Scanning: ${scanTarget}`);
      this.info(`🎯 Scan Type: ${scanType}`);
      this.info(`⚠️  Severity: ${severityUpper}`);
      
      // Create temporary output file for JSON results
      const jsonOutputPath = path.join(os.tmpdir(), `trivy-scan-results-${Date.now()}.json`);
      
      // Build command arguments
      const args = [
        scanType,
        '--severity', severityUpper,
        '--format', 'json',
        '--output', jsonOutputPath,
        '--exit-code', '0', // Always return 0, we handle failures in orchestrator
        '--quiet' // Reduce noise
      ];
      
      if (ignoreUnfixed) {
        args.push('--ignore-unfixed');
      }
      
      // Add skip dirs to avoid scanning scanner's own files
      args.push('--skip-dirs', 'node_modules,.git,.gitlab');
      
      args.push(scanTarget);
      
      const command = `"${this.binaryPath || SCANNER_BINARY}" ${args.join(' ')}`;
      this.info(`📝 Running: ${command}`);
      
      // Execute scan
      try {
        execSync(command, {
          cwd: path.dirname(scanTarget),
          stdio: 'inherit',
          env: process.env
        });
      } catch (execError) {
        // Log but don't fail - we set --exit-code 0
        this.warning(`Scan completed with warnings: ${execError.message}`);
      }
      
      this.info(`✅ Scan completed`);
      
      // Parse results
      this.info(`📄 Reading results from: ${jsonOutputPath}`);
      
      // Check if file was created
      if (!fs.existsSync(jsonOutputPath)) {
        this.error(`❌ Output file was not created: ${jsonOutputPath}`);
        throw new Error('Trivy did not produce output file');
      }
      
      const results = this.parseResults(jsonOutputPath);
      
      // Clean up
      try {
        if (fs.existsSync(jsonOutputPath)) {
          fs.unlinkSync(jsonOutputPath);
        }
      } catch (cleanupError) {
        this.debug(`Failed to cleanup temp file: ${cleanupError.message}`);
      }
      
      return results;
      
    } catch (error) {
      this.error(`❌ Trivy scan failed: ${error.message}`);
      this.debug(`Stack: ${error.stack}`);
      throw error;
    }
  }

  /**
   * Parse Trivy JSON output
   */
  parseResults(jsonPath) {
    try {
      if (!fs.existsSync(jsonPath)) {
        this.warning(`⚠️ JSON output file not found: ${jsonPath}`);
        return {
          total: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          vulnerabilities: []
        };
      }
      
      const stats = fs.statSync(jsonPath);
      this.info(`📊 JSON file size: ${stats.size} bytes`);
      
      const jsonContent = fs.readFileSync(jsonPath, 'utf8');
      
      if (!jsonContent || jsonContent.trim() === '') {
        this.warning('⚠️ JSON output file is empty');
        return {
          total: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          vulnerabilities: []
        };
      }
      
      this.debug(`First 200 chars of JSON: ${jsonContent.substring(0, 200)}`);
      
      const data = JSON.parse(jsonContent);
      
      let criticalCount = 0;
      let highCount = 0;
      let mediumCount = 0;
      let lowCount = 0;
      const vulnerabilities = [];
      
      // Check if Results exists and has data
      if (data.Results && Array.isArray(data.Results)) {
        this.info(`📦 Processing ${data.Results.length} result(s)`);
        
        data.Results.forEach((result, idx) => {
          this.debug(`Result ${idx + 1}: Type=${result.Type}, Target=${result.Target}`);
          
          if (result.Vulnerabilities && Array.isArray(result.Vulnerabilities)) {
            this.info(`   📋 Result ${idx + 1} (${result.Type || 'unknown'}): ${result.Vulnerabilities.length} vulnerabilities`);
            
            result.Vulnerabilities.forEach(vuln => {
              vulnerabilities.push({
                id: vuln.VulnerabilityID,
                severity: vuln.Severity,
                package: vuln.PkgName,
                version: vuln.InstalledVersion,
                fixedVersion: vuln.FixedVersion,
                title: vuln.Title
              });
              
              switch (vuln.Severity) {
                case 'CRITICAL':
                  criticalCount++;
                  break;
                case 'HIGH':
                  highCount++;
                  break;
                case 'MEDIUM':
                  mediumCount++;
                  break;
                case 'LOW':
                  lowCount++;
                  break;
              }
            });
          } else {
            this.info(`   ✅ Result ${idx + 1} (${result.Type || 'unknown'}): No vulnerabilities`);
          }
        });
      } else {
        this.warning('⚠️ No Results array found in JSON output');
        if (data) {
          this.debug(`JSON keys: ${Object.keys(data).join(', ')}`);
        }
      }
      
      const totalCount = criticalCount + highCount + mediumCount + lowCount;
      
      // Log scanner-specific results
      this.info(`\n✨ Trivy Scan Complete:`);
      this.info(`   📊 Total: ${totalCount} vulnerabilities`);
      this.info(`   🔴 Critical: ${criticalCount}`);
      this.info(`   🟠 High: ${highCount}`);
      this.info(`   🟡 Medium: ${mediumCount}`);
      this.info(`   🟢 Low: ${lowCount}`);
      
      return {
        total: totalCount,
        critical: criticalCount,
        high: highCount,
        medium: mediumCount,
        low: lowCount,
        vulnerabilities
      };
      
    } catch (error) {
      this.error(`❌ Failed to parse Trivy results: ${error.message}`);
      this.debug(`Stack: ${error.stack}`);
      return {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        vulnerabilities: []
      };
    }
  }
}

// Export singleton instance
module.exports = new TrivyScanner();

/***/ }),

/***/ 611:
/***/ ((module) => {

"use strict";
module.exports = require("http");

/***/ }),

/***/ 692:
/***/ ((module) => {

"use strict";
module.exports = require("https");

/***/ }),

/***/ 857:
/***/ ((module) => {

"use strict";
module.exports = require("os");

/***/ }),

/***/ 896:
/***/ ((module) => {

"use strict";
module.exports = require("fs");

/***/ }),

/***/ 928:
/***/ ((module) => {

"use strict";
module.exports = require("path");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
const trivyScanner = __webpack_require__(513);
// const cdxgenScanner = require('./scanners/sbom');
// const secretDetectorScanner = require('./scanners/secret-detector');
const path = __webpack_require__(928);
const fs = __webpack_require__(896);

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

    for (const scanner of this.scanners) {
      try {
        this.info(`\n▶️  Running ${scanner.name}...`);
        const result = await scanner.scan(scanConfig);
        
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

  /**
   * Display consolidated results
   */
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
      const https = __webpack_require__(692);
      const http = __webpack_require__(611);
      const url = __webpack_require__(16);
      
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
    // orchestrator.registerScanner(secretDetectorScanner);
    
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
module.exports = __webpack_exports__;
/******/ })()
;