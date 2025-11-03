const exec = require('child_process').execSync;
const execAsync = require('util').promisify(require('child_process').exec);
const fs = require('fs');
const os = require('os');
const path = require('path');

class ConfigScanner {
    constructor() {
        this.name = 'Trivy config Scanner';
        this.binaryPath = null; // Path to Trivy binary
    }

    log(message) {
        console.log(message);
    }

    logWarning(message) {
        console.warn(`WARNING: ${message}`);
    }

    logError(message) {
        console.error(`ERROR: ${message}`);
    }

    logDebug(message) {
        if (process.env.DEBUG === 'true') {
            console.log(`DEBUG: ${message}`);
        }
    }

    async install() {
        const trivyInstaller = require('./trivy');
        if (typeof trivyInstaller.install === 'function') {
            this.log('📦 Installing Trivy for Config Scanner using Trivy scanner installer...');
            this.binaryPath = await trivyInstaller.install(); // Should return full binary path
            this.log(`🛠️ Trivy binary path: ${this.binaryPath}`);
        } else {
            this.log('ℹ️ Skipping install — assuming Trivy is already installed.');
            this.binaryPath = 'trivy'; // fallback
        }
    }

    async scan(config) {
        try {
            const { scanTarget, severity } = config;

            if (!fs.existsSync(scanTarget)) {
                throw new Error(`Scan target does not exist: ${scanTarget}`);
            }

            const severityUpper = severity.toUpperCase();
            this.log(`🔍 Scanning: ${scanTarget}`);
            this.log(`⚠️  Severity: ${severityUpper}`);

            const reportPath = path.join(os.tmpdir(), `trivy-config-scan-${Date.now()}.json`);

            // Build args array
            const args = ['config', '--format', 'json', '--output', reportPath];
            
            // Add severity filter if specified
            if (severityUpper && severityUpper !== 'ALL') {
                args.push('--severity', severityUpper);
            }
            args.push(scanTarget);

            const command = `${this.binaryPath} ${args.join(' ')}`;
            this.log(`📝 Running: ${command}`);

            let stdoutOutput = '';
            let stderrOutput = '';
            let exitCode = 0;

            try {
                const { stdout, stderr } = await execAsync(command, {
                    cwd: path.dirname(scanTarget),
                    maxBuffer: 10 * 1024 * 1024, // 10MB buffer
                    encoding: 'utf8'
                });
                stdoutOutput = stdout;
                stderrOutput = stderr;
            } catch (error) {
                // Command failed, but we still want to process results
                exitCode = error.code || 1;
                stdoutOutput = error.stdout || '';
                stderrOutput = error.stderr || '';
            }

            this.log(`✅ Scan completed with exit code: ${exitCode}`);
            if (stderrOutput && exitCode !== 0) {
                this.logWarning(`Stderr output: ${stderrOutput}`);
            }

            if (!fs.existsSync(reportPath)) {
                this.logError(`❌ Output file was not created: ${reportPath}`);
                this.logError(`Stdout: ${stdoutOutput}`);
                this.logError(`Stderr: ${stderrOutput}`);
                throw new Error('Trivy did not produce output file');
            }

            const results = this.parseResults(reportPath);

            try { fs.unlinkSync(reportPath); } catch { }

            return results;

        } catch (error) {
            this.logError(`❌ Trivy config scan failed: ${error.message}`);
            this.logDebug(error.stack);
            throw error;
        }
    }

    parseResults(jsonPath) {
        try {
            if (!fs.existsSync(jsonPath)) {
                return {
                    total: 0,
                    totalFiles: 0,
                    files: [],
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0,
                    misconfigurations: []
                };
            }

            const data = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
            const files = [];
            const misconfigurations = [];
            let critical = 0;
            let high = 0;
            let medium = 0;
            let low = 0;
            let total = 0;

            if (Array.isArray(data.Results)) {
                data.Results.forEach(result => {
                    if (result.Target) {
                        files.push(result.Target);
                    }

                    // Count misconfigurations by severity
                    if (Array.isArray(result.Misconfigurations)) {
                        result.Misconfigurations.forEach(misconfiguration => {
                            const severity = misconfiguration.Severity?.toUpperCase();
                            
                            switch(severity) {
                                case 'CRITICAL':
                                    critical++;
                                    break;
                                case 'HIGH':
                                    high++;
                                    break;
                                case 'MEDIUM':
                                    medium++;
                                    break;
                                case 'LOW':
                                    low++;
                                    break;
                            }
                            total++;

                            misconfigurations.push({
                                File: result.Target || 'Unknown',
                                Issue: misconfiguration.Title || misconfiguration.ID || 'N/A',
                                Severity: severity || 'UNKNOWN',
                                Line: misconfiguration.CauseMetadata?.StartLine || 'N/A'
                            });
                        });
                    }
                });
            }

            const fileCount = files.length;
            // Log detected files
            if (fileCount > 0) {
                this.log(`📁 Detected config files: ${fileCount}`);
                files.forEach((file, index) => {
                    this.log(`   ${index + 1}. ${file}`);
                });
            }

            return {
                total: fileCount,
                totalFiles: fileCount,
                files,
                critical,
                high,
                medium,
                low,
                misconfigurations
            };

        } catch (err) {
            this.logError(`❌ Failed to parse Trivy results: ${err.message}`);
            return {
                total: 0,
                totalFiles: 0,
                files: [],
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                misconfigurations: []
            };
        }
    }
}

module.exports = new ConfigScanner();