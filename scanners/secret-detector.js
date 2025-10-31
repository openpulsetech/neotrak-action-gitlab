const exec = require('child_process').execSync;
const execAsync = require('child_process').exec;
const os = require('os');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

const GITLEAKS_VERSION = 'v8.27.2';
const GITLEAKS_BINARY = 'gitleaks';

const skipFiles = [
  'package.json',
  'package-lock.json',
  'pom.xml',
  'build.gradle',
  'requirements.txt',
  'README.md',
  '.gitignore'
];

class SecretDetectorScanner {
  constructor() {
    this.name = 'Secret Detector (Gitleaks)';
    this.binaryPath = null;
  }

  log(message, level = 'info') {
    const prefix = {
      info: '📋',
      error: '❌',
      warning: '⚠️',
      debug: '🔍'
    }[level] || '•';
    
    console.log(`${prefix} ${message}`);
  }

  async install() {
    try {
      this.log(`Installing Gitleaks ${GITLEAKS_VERSION}...`, 'info');
      
      const platform = os.platform();
      const arch = os.arch() === 'x64' ? 'x64' : 'arm64';
      
      let downloadUrl;
      let fileName;
      let binaryName;
      
      if (platform === 'linux') {
        fileName = `gitleaks_${GITLEAKS_VERSION.substring(1)}_linux_${arch}.tar.gz`;
        downloadUrl = `https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/${fileName}`;
        binaryName = 'gitleaks';
      } else if (platform === 'darwin') {
        fileName = `gitleaks_${GITLEAKS_VERSION.substring(1)}_darwin_${arch}.tar.gz`;
        downloadUrl = `https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/${fileName}`;
        binaryName = 'gitleaks';
      } else if (platform === 'win32') {
        fileName = `gitleaks_${GITLEAKS_VERSION.substring(1)}_windows_${arch}.zip`;
        downloadUrl = `https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/${fileName}`;
        binaryName = 'gitleaks.exe';
      } else {
        throw new Error(`Unsupported platform: ${platform}`);
      }

      this.log(`Downloading Gitleaks from: ${downloadUrl}`, 'debug');

      // Create temp directory for download
      const tempDir = path.join(os.tmpdir(), `gitleaks_${Date.now()}`);
      if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir, { recursive: true });
      }

      const downloadPath = path.join(tempDir, fileName);

      // Download the file using curl or wget
      try {
        exec(`curl -L -o "${downloadPath}" "${downloadUrl}"`, { stdio: 'inherit' });
      } catch (e) {
        // Fallback to wget if curl fails
        exec(`wget -O "${downloadPath}" "${downloadUrl}"`, { stdio: 'inherit' });
      }

      this.log(`Downloaded to: ${downloadPath}`, 'debug');

      // Extract the archive
      const extractDir = path.join(tempDir, 'extracted');
      if (!fs.existsSync(extractDir)) {
        fs.mkdirSync(extractDir, { recursive: true });
      }

      if (platform === 'win32') {
        exec(`unzip "${downloadPath}" -d "${extractDir}"`, { stdio: 'inherit' });
      } else {
        exec(`tar -xzf "${downloadPath}" -C "${extractDir}"`, { stdio: 'inherit' });
      }

      this.log(`Extracted to: ${extractDir}`, 'debug');

      // Find the binary
      const binaryPath = path.join(extractDir, binaryName);
      if (!fs.existsSync(binaryPath)) {
        throw new Error(`Gitleaks binary not found at: ${binaryPath}`);
      }

      // Make binary executable (for Unix systems)
      if (platform !== 'win32') {
        fs.chmodSync(binaryPath, '755');
      }

      // Move to a permanent location
      const binDir = path.join(os.homedir(), '.local', 'bin');
      if (!fs.existsSync(binDir)) {
        fs.mkdirSync(binDir, { recursive: true });
      }

      this.binaryPath = path.join(binDir, binaryName);
      fs.copyFileSync(binaryPath, this.binaryPath);

      if (platform !== 'win32') {
        fs.chmodSync(this.binaryPath, '755');
      }
      
      // Add to PATH for this session
      process.env.PATH = `${binDir}:${process.env.PATH}`;
      
      this.log(`Gitleaks installed successfully at: ${this.binaryPath}`, 'info');
      return this.binaryPath;
    } catch (error) {
      throw new Error(`Failed to install Gitleaks: ${error.message}`);
    }
  }

  createCustomRules() {
    return `
[[rules]]
id = "strict-secret-detection"
description = "Detect likely passwords or secrets with high entropy"
regex = '''(?i)(password|passwd|pwd|secret|key|token|auth|access)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9@#\\-_$%!]{10,})["']'''
tags = ["key", "secret", "generic", "password"]

[[rules]]
id = "aws-secret"
description = "AWS Secret Access Key"
regex = '''(?i)aws(.{0,20})?(secret|access)?(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]'''
tags = ["aws", "key", "secret"]

[[rules]]
id = "aws-key"
description = "AWS Access Key ID"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["aws", "key"]

[[rules]]
id = "github-token"
description = "GitHub Personal Access Token"
regex = '''ghp_[A-Za-z0-9_]{36}'''
tags = ["github", "token"]

[[rules]]
id = "gitlab-token"
description = "GitLab Personal Access Token"
regex = '''glpat-[A-Za-z0-9\\-_]{20}'''
tags = ["gitlab", "token"]

[[rules]]
id = "jwt"
description = "JSON Web Token"
regex = '''eyJ[A-Za-z0-9-_]+\\.eyJ[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+'''
tags = ["token", "jwt"]

[[rules]]
id = "firebase-api-key"
description = "Firebase API Key"
regex = '''AIza[0-9A-Za-z\\-_]{35}'''
tags = ["firebase", "apikey"]
`;
  }

  createTempRulesFile() {
    const rulesPath = path.join(os.tmpdir(), 'gitleaks-custom-rules.toml');
    fs.writeFileSync(rulesPath, this.createCustomRules());
    return rulesPath;
  }

  async runGitleaks(scanDir, reportPath, rulesPath) {
    return new Promise((resolve, reject) => {
      const args = ['detect', '--source', scanDir, '--report-path', reportPath, '--config', rulesPath, '--no-banner'];
      const command = `"${this.binaryPath}" ${args.join(' ')}`;
      
      this.log(`Running Gitleaks: ${command}`, 'debug');

      execAsync(command, (error, stdout, stderr) => {
        if (stdout) {
          this.log(`Gitleaks STDOUT: ${stdout}`, 'debug');
        }
        if (stderr && stderr.trim()) {
          this.log(`Gitleaks STDERR: ${stderr}`, 'warning');
        }
        
        // Gitleaks returns exit code 1 when secrets are found, which is expected
        if (error && error.code !== 1) {
          reject(error);
        } else {
          resolve(error ? error.code : 0);
        }
      });
    });
  }

  async checkReport(reportPath) {
    return new Promise((resolve, reject) => {
      fs.readFile(reportPath, 'utf8', (err, data) => {
        if (err) return reject(err);

        try {
          const report = JSON.parse(data);
          resolve(report.length ? report : "No secrets detected.");
        } catch (e) {
          reject(new Error("Invalid JSON in gitleaks report."));
        }
      });
    });
  }

  mapToSBOMSecret(item) {
    const fixedFile = this.fixFilePath(item.File);
    return {
      RuleID: item.RuleID,
      Description: item.Description,
      File: fixedFile,
      Match: item.Match,
      Secret: item.Secret,
      StartLine: String(item.StartLine ?? ''),
      EndLine: String(item.EndLine ?? ''),
      StartColumn: String(item.StartColumn ?? ''),
      EndColumn: String(item.EndColumn ?? ''),
    };
  }

  fixFilePath(filePath) {
    if (!filePath) return '///////';

    let segments = filePath.split('/');
    const requiredSegments = 8;

    const nonEmptyCount = segments.filter(Boolean).length;

    while (nonEmptyCount + segments.length - nonEmptyCount < requiredSegments) {
      segments.unshift('');
    }

    return segments.join('/');
  }

  async sendSecretsToApi(projectId, secretItems) {
    const apiUrl = `https://dev.neoTrak.io/open-pulse/project/update-secrets/${projectId}`;
    const secretsData = secretItems.map(item => this.mapToSBOMSecret(item));

    const headers = {
      'Content-Type': 'application/json',
    };

    const apiKey = process.env.X_API_KEY;
    const secretKey = process.env.X_SECRET_KEY;
    const tenantKey = process.env.X_TENANT_KEY;

    if (apiKey) headers['x-api-key'] = apiKey;
    if (secretKey) headers['x-secret-key'] = secretKey;
    if (tenantKey) headers['x-tenant-key'] = tenantKey;

    try {
      this.log('Sending secrets to API...', 'debug');

      const response = await axios.post(apiUrl, secretsData, {
        headers,
        timeout: 60000,
      });

      if (response.status >= 200 && response.status < 300) {
        this.log('Secrets updated successfully in SBOM API.', 'info');
      } else {
        this.log(`Failed to update secrets. Status: ${response.status}`, 'error');
        this.log(`Response body: ${JSON.stringify(response.data)}`, 'error');
      }
    } catch (err) {
      this.log(`Error sending secrets to SBOM API: ${err.message || err}`, 'error');
    }
  }

  async scan(config) {
    try {
      const startTime = Date.now();
      const scanDir = config.scanTarget || config.workspaceDir || process.env.CI_PROJECT_DIR || '.';
      const reportPath = path.join(os.tmpdir(), `gitleaks_${Date.now()}_report.json`);
      const rulesPath = this.createTempRulesFile();

      this.log(`Scanning for secrets in: ${scanDir}`, 'info');

      // Set GIT safe directory for GitLab CI context
      try {
        exec(`git config --global --add safe.directory "${scanDir}"`, { stdio: 'inherit' });
      } catch (e) {
        this.log("Could not configure Git safe directory (not a git repo?)", 'warning');
      }

      await this.runGitleaks(scanDir, reportPath, rulesPath);
      const result = await this.checkReport(reportPath);

      const endTime = Date.now();

      const filtered = Array.isArray(result)
        ? result.filter(item =>
          !skipFiles.includes(path.basename(item.File)) &&
          !item.File.includes('node_modules') &&
          !/["']?\$\{?[A-Z0-9_]+\}?["']?/.test(item.Match)
        )
        : result;

      const filteredSecrets = Array.isArray(filtered)
        ? filtered.map(item => ({
            Description: item.Description,
            File: `//////${item.File}`,
            Match: item.Match,
            StartLine: String(item.StartLine),
            EndLine: String(item.EndLine),
            StartColumn: String(item.StartColumn),
            EndColumn: String(item.EndColumn),
          }))
        : [];

      const durationMs = endTime - startTime;
      const durationMin = Math.floor(durationMs / 60000);
      const durationSec = Math.floor((durationMs % 60000) / 1000);
      const durationStr = `${durationMin}min ${durationSec}s`;

      this.log(`Secrets detected: ${Array.isArray(filtered) ? filtered.length : 0}`, 'info');
      this.log(`Scan duration: ${durationStr}`, 'info');

      // Send secrets to API if found and PROJECT_ID is set
      if (filtered !== "No secrets detected." && Array.isArray(filtered) && filtered.length > 0) {
        // Use GitLab CI environment variable if PROJECT_ID not set
        const projectId = process.env.PROJECT_ID || process.env.CI_PROJECT_ID;
        if (projectId) {
          this.log(`Raw secrets data: ${JSON.stringify(filtered, null, 2)}`, 'debug');
          await this.sendSecretsToApi(projectId, filtered);
        } else {
          this.log('PROJECT_ID environment variable not set. Skipping API upload.', 'warning');
        }
      }

      // Clean up temporary files
      try {
        fs.unlinkSync(rulesPath);
        if (fs.existsSync(reportPath)) {
          fs.unlinkSync(reportPath);
        }
      } catch (e) {
        this.log('Could not clean up temporary files', 'warning');
      }

      // Return results in the format expected by orchestrator
      const secretCount = Array.isArray(filtered) ? filtered.length : 0;
      return {
        total: secretCount,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        vulnerabilities: filteredSecrets,
        secrets: filteredSecrets,
        duration: durationStr
      };
    } catch (error) {
      this.log(`Secret detection scan failed: ${error.message}`, 'error');
      throw error;
    }
  }
}

module.exports = new SecretDetectorScanner();