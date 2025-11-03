const fs = require('fs');
const os = require('os');
const path = require('path');
const { execSync } = require('child_process');

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
  // async scan(config) {
  //   try {
  //     const {
  //       scanType,
  //       scanTarget,
  //       severity,
  //       ignoreUnfixed
  //     } = config;
      
  //     // Validate scan target exists
  //     if (!fs.existsSync(scanTarget)) {
  //       throw new Error(`Scan target does not exist: ${scanTarget}`);
  //     }
      
  //     // Convert severity to uppercase (Trivy expects uppercase)
  //     const severityUpper = severity.toUpperCase();
      
  //     this.info(`🔍 Scanning: ${scanTarget}`);
  //     this.info(`🎯 Scan Type: ${scanType}`);
  //     this.info(`⚠️  Severity: ${severityUpper}`);
      
  //     // Create temporary output file for JSON results
  //     const jsonOutputPath = path.join(os.tmpdir(), `trivy-scan-results-${Date.now()}.json`);
      
  //     // Build command arguments
  //     const args = [
  //       scanType,
  //       '--severity', severityUpper,
  //       '--format', 'json',
  //       '--output', jsonOutputPath,
  //       '--exit-code', '0', // Always return 0, we handle failures in orchestrator
  //       '--quiet' // Reduce noise
  //     ];
      
  //     if (ignoreUnfixed) {
  //       args.push('--ignore-unfixed');
  //     }
      
  //     // Add skip dirs to avoid scanning scanner's own files
  //     args.push('--skip-dirs', 'node_modules,.git,.gitlab');
      
  //     args.push(scanTarget);
      
  //     const command = `"${this.binaryPath || SCANNER_BINARY}" ${args.join(' ')}`;
  //     this.info(`📝 Running: ${command}`);
      
  //     // Execute scan
  //     try {
  //       execSync(command, {
  //         cwd: path.dirname(scanTarget),
  //         stdio: 'inherit',
  //         env: process.env
  //       });
  //     } catch (execError) {
  //       // Log but don't fail - we set --exit-code 0
  //       this.warning(`Scan completed with warnings: ${execError.message}`);
  //     }
      
  //     this.info(`✅ Scan completed`);
      
  //     // Parse results
  //     this.info(`📄 Reading results from: ${jsonOutputPath}`);
      
  //     // Check if file was created
  //     if (!fs.existsSync(jsonOutputPath)) {
  //       this.error(`❌ Output file was not created: ${jsonOutputPath}`);
  //       throw new Error('Trivy did not produce output file');
  //     }
      
  //     const results = this.parseResults(jsonOutputPath);
      
  //     // Clean up
  //     try {
  //       if (fs.existsSync(jsonOutputPath)) {
  //         fs.unlinkSync(jsonOutputPath);
  //       }
  //     } catch (cleanupError) {
  //       this.debug(`Failed to cleanup temp file: ${cleanupError.message}`);
  //     }
      
  //     return results;
      
  //   } catch (error) {
  //     this.error(`❌ Trivy scan failed: ${error.message}`);
  //     this.debug(`Stack: ${error.stack}`);
  //     throw error;
  //   }
  // }

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
    
    // ADD THESE DEBUG LINES ⬇️
    const fileStats = fs.statSync(jsonOutputPath);
    this.info(`✅ Output file exists, size: ${fileStats.size} bytes`);
    this.info(`🔄 About to call parseResults...`);
    // END DEBUG LINES ⬆️
    
    const results = this.parseResults(jsonOutputPath);
    
    this.info(`✅ parseResults completed, returned object with total: ${results ? results.total : 'null'}`);
    // END DEBUG LINE ⬆️
    
    // Clean up
    this.info(`🧹 Starting cleanup...`); 
    try {
      if (fs.existsSync(jsonOutputPath)) {
        fs.unlinkSync(jsonOutputPath);
        this.info(`🧹 Temp file deleted`);
      }
    } catch (cleanupError) {
      this.debug(`Failed to cleanup temp file: ${cleanupError.message}`);
    }
    
    this.info(`🎯 About to return results: ${JSON.stringify(results)}`);
    
    return results;
    
  } catch (error) {
    this.error(`❌ Trivy scan failed: ${error.message}`);
    this.debug(`Stack: ${error.stack}`);
    throw error; // ⚠️ This might be preventing results from returning
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

// Export singleton instance of TrivyScanner
module.exports = new TrivyScanner();