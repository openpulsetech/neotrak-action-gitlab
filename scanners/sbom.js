const execSync = require('child_process').execSync;
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const os = require('os');
const fs = require('fs');
const path = require('path');
const trivyScanner = require('./trivy');

const CDXGEN_PACKAGE = '@cyclonedx/cdxgen';
const CDXGEN_VERSION = '11.9.0';
const CDXGEN_BINARY = 'cdxgen';

class CdxgenScanner {
  constructor() {
    this.name = 'CDXgen SBOM Generator';
    this.binaryPath = null;
    this.trivyBinaryPath = null;
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
    if (process.env.DEBUG === 'true' || process.env.CI_DEBUG_TRACE === 'true') {
      console.log(`DEBUG: ${message}`);
    }
  }

  async install() {
    try {
      const installDir = path.join(os.tmpdir(), 'cdxgen-install');
      this.log(`📦 Installing ${CDXGEN_PACKAGE}@${CDXGEN_VERSION}...`);

      // Create temporary install directory
      if (!fs.existsSync(installDir)) {
        fs.mkdirSync(installDir, { recursive: true });
      }

      // Install cdxgen locally with specific version
      try {
        execSync(`npm install ${CDXGEN_PACKAGE}@${CDXGEN_VERSION}`, {
          cwd: installDir,
          stdio: ['ignore', 'ignore', 'pipe'] // Suppress output but show errors
        });
      } catch (error) {
        throw new Error(`npm install failed: ${error.message}`);
      }

      // Find the installed binary
      const binaryPath = path.join(installDir, 'node_modules', '.bin', CDXGEN_BINARY);

      if (!fs.existsSync(binaryPath)) {
        throw new Error(`CDXgen binary not found at: ${binaryPath}`);
      }

      // Make binary executable (for Unix systems)
      if (os.platform() !== 'win32') {
        fs.chmodSync(binaryPath, '755');
      }

      this.log(`✅ ${CDXGEN_BINARY} installed successfully at: ${binaryPath}`);
      this.binaryPath = binaryPath;
      return binaryPath;
    } catch (error) {
      throw new Error(`Failed to install ${CDXGEN_PACKAGE}: ${error.message}`);
    }
  }

  async generateSBOM(targetDirectory) {
    try {
      if (!fs.existsSync(targetDirectory)) {
        throw new Error(`Target directory does not exist: ${targetDirectory}`);
      }

      const outputFilePath = path.join(targetDirectory, 'sbom.json');
      const fullOutputPath = path.resolve(outputFilePath);
      
      this.log(`🔍 Generating SBOM for: ${targetDirectory}`);
      this.log(`📂 Target directory contents:`);
      
      // List all files in the target directory
      try {
        const files = fs.readdirSync(targetDirectory);
        if (files.length === 0) {
          this.log(`   ⚠️  Directory is empty!`);
        } else {
          files.forEach(file => {
            const filePath = path.join(targetDirectory, file);
            const stats = fs.statSync(filePath);
            const type = stats.isDirectory() ? '[DIR]' : '[FILE]';
            this.log(`   ${type} ${file}`);
          });
        }
      } catch (err) {
        this.logError(`   Failed to list directory: ${err.message}`);
      }

      const args = [
        '--spec-version', '1.4',
        '--deep',                       // Scan subdirectories
        '--output', outputFilePath,
        targetDirectory
      ];

      const command = `${this.binaryPath} ${args.join(' ')}`;
      this.log(`📝 Running: ${command}`);
      this.log(`📄 Expected output file: ${fullOutputPath}`);

      let stdout = '';
      let stderr = '';

      try {
        // Capture output to see what CDXgen is doing
        const result = execSync(command, {
          cwd: targetDirectory,
          encoding: 'utf8',
          maxBuffer: 10 * 1024 * 1024
        });
        stdout = result;
      } catch (error) {
        // CDXgen might exit with non-zero code but still generate output
        stderr = error.stderr || '';
        stdout = error.stdout || '';
        this.log(`⚠️  CDXgen exited with code: ${error.status}`);
        
        if (stdout && stdout.trim()) {
          this.log(`📤 CDXgen stdout:\n${stdout.substring(0, 1000)}`);
        }
        if (stderr && stderr.trim()) {
          this.log(`📤 CDXgen stderr:\n${stderr.substring(0, 1000)}`);
        }
      }

      this.log(`✅ SBOM generation completed`);
      
      // List directory again to see if any file was created
      this.log(`📂 Directory contents after CDXgen:`);
      try {
        const filesAfter = fs.readdirSync(targetDirectory);
        filesAfter.forEach(file => {
          if (file.includes('sbom') || file.includes('bom') || file.includes('cdx')) {
            this.log(`   🎯 ${file} (possible SBOM file)`);
          }
        });
      } catch (err) {
        this.logError(`   Failed to list directory: ${err.message}`);
      }

      if (!fs.existsSync(fullOutputPath)) {
        this.logError(`❌ Output file not created: ${fullOutputPath}`);
        throw new Error('CDXgen did not generate SBOM output file');
      }

      return fullOutputPath;
    } catch (error) {
      this.logError(`❌ CDXgen SBOM generation failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Required by orchestrator
   */
  async scan(config) {
    try {
      const targetDir = config.scanTarget || '.';

      // Uncomment the next line to force generateSBOM to fail
      // throw new Error('Forced error to test fallback');

      const sbomPath = await this.generateSBOM(targetDir);
      this.log(`📦 SBOM generated: ${sbomPath}`);
    
      // Ensure Trivy is installed
      if (!trivyScanner.binaryPath) {
        this.log('🔧 Trivy not found, installing Trivy scanner in sbom...');
        await trivyScanner.install();
      }
      this.trivyBinaryPath = trivyScanner.binaryPath;

      const trivyArgs = [
        'sbom',
        '--format', 'json',
        '--quiet',
        sbomPath
      ];

      const command = `${this.trivyBinaryPath} ${trivyArgs.join(' ')}`;
      console.log(`🛠️ Using Trivy binary at: ${this.trivyBinaryPath}`);
      // console.log(`🧩 Running command: trivy ${trivyArgs.join(' ')}`);

      let stdoutData = '';

      try {
        const { stdout } = await execAsync(command, {
          maxBuffer: 10 * 1024 * 1024,
          encoding: 'utf8'
        });
        stdoutData = stdout;
      } catch (error) {
        // Trivy might return non-zero exit code even with valid results
        stdoutData = error.stdout || '';
        if (!stdoutData) {
          throw error;
        }
      }

      if (stdoutData.trim() === '') {
        this.logWarning('⚠️  No vulnerabilities found');
        return {
          total: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          vulnerabilities: [],
          sbomPath
        };
      }

      const data = JSON.parse(stdoutData);
      const vulns = (data.Results || []).flatMap(r => r.Vulnerabilities || []).filter(v => v);

      const countBySeverity = {
        CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0
      };

      vulns.forEach(vuln => {
        const sev = (vuln.Severity || 'UNKNOWN').toUpperCase();
        if (countBySeverity[sev] !== undefined) {
          countBySeverity[sev]++;
        }
      });

      this.log(`📊 Vulnerability Summary:`);
      this.log(`   CRITICAL: ${countBySeverity.CRITICAL}`);
      this.log(`   HIGH:     ${countBySeverity.HIGH}`);
      this.log(`   MEDIUM:   ${countBySeverity.MEDIUM}`);
      this.log(`   LOW:      ${countBySeverity.LOW}`);
      this.log(`   TOTAL:    ${vulns.length}`);

      return {
        total: vulns.length,
        critical: countBySeverity.CRITICAL,
        high: countBySeverity.HIGH,
        medium: countBySeverity.MEDIUM,
        low: countBySeverity.LOW,
        vulnerabilities: vulns,
        sbomPath
      };

    } catch (error) {
      this.logError(`❌ Scan failed: ${error.message}`);
      // throw error;
      this.log('➡️ Falling back to Trivy scanner...');

      // Fallback: call trivy.js scanner directly
      return await trivyScanner.scan(config);
    }
  }

}

module.exports = new CdxgenScanner();

// const execSync = require('child_process').execSync;
// const { exec } = require('child_process');
// const { promisify } = require('util');
// const execAsync = promisify(exec);
// const os = require('os');
// const fs = require('fs');
// const path = require('path');

// const trivyScanner = require('./trivy');

// const CDXGEN_PACKAGE = '@cyclonedx/cdxgen';
// const CDXGEN_VERSION = '11.9.0';
// const CDXGEN_BINARY = 'cdxgen';

// class CdxgenScanner {
//   constructor() {
//     this.name = 'CDXgen SBOM Generator';
//     this.binaryPath = null;
//     this.trivyBinaryPath = null;
//   }

//   log(message) {
//     console.log(message);
//   }

//   logWarning(message) {
//     console.warn(`WARNING: ${message}`);
//   }

//   logError(message) {
//     console.error(`ERROR: ${message}`);
//   }

//   logDebug(message) {
//     if (process.env.DEBUG === 'true' || process.env.CI_DEBUG_TRACE === 'true') {
//       console.log(`DEBUG: ${message}`);
//     }
//   }

//   async install() {
//     try {
//       const installDir = path.join(os.tmpdir(), 'cdxgen-install');
//       this.log(`📦 Installing ${CDXGEN_PACKAGE}@${CDXGEN_VERSION}...`);

//       // Create temporary install directory
//       if (!fs.existsSync(installDir)) {
//         fs.mkdirSync(installDir, { recursive: true });
//       }

//       // Install cdxgen locally with specific version
//       try {
//         execSync(`npm install ${CDXGEN_PACKAGE}@${CDXGEN_VERSION}`, {
//           cwd: installDir,
//           stdio: 'inherit'
//         });
//       } catch (error) {
//         throw new Error(`npm install failed: ${error.message}`);
//       }

//       // Find the installed binary
//       const binaryPath = path.join(installDir, 'node_modules', '.bin', CDXGEN_BINARY);

//       if (!fs.existsSync(binaryPath)) {
//         throw new Error(`CDXgen binary not found at: ${binaryPath}`);
//       }

//       // Make binary executable (for Unix systems)
//       if (os.platform() !== 'win32') {
//         fs.chmodSync(binaryPath, '755');
//       }

//       this.log(`✅ ${CDXGEN_BINARY} installed successfully at: ${binaryPath}`);
//       this.binaryPath = binaryPath;
//       return binaryPath;
//     } catch (error) {
//       throw new Error(`Failed to install ${CDXGEN_PACKAGE}: ${error.message}`);
//     }
//   }

//   async generateSBOM(targetDirectory) {
//     try {
//       if (!fs.existsSync(targetDirectory)) {
//         throw new Error(`Target directory does not exist: ${targetDirectory}`);
//       }

//       const outputFilePath = path.join(targetDirectory, `sbom.json`);
//       const fullOutputPath = path.resolve(outputFilePath);
      
//       this.log(`🔍 Generating SBOM for: ${targetDirectory}`);

//       const args = [
//         '--spec-version', '1.4',
//         '--deep',                       // Scan subdirectories
//         '--output', outputFilePath,
//         targetDirectory
//       ];

//       const command = `${this.binaryPath} ${args.join(' ')}`;
//       this.log(`📝 Running: ${command}`);

//       try {
//         // Execute command with suppressed output
//         execSync(command, {
//           cwd: targetDirectory,
//           stdio: ['ignore', 'pipe', 'pipe'], // Suppress stdout/stderr
//           maxBuffer: 10 * 1024 * 1024 // 10MB buffer
//         });
//       } catch (error) {
//         // CDXgen might exit with non-zero code but still generate output
//         this.logDebug(`CDXgen exited with code: ${error.status}`);
//       }

//       this.log(`✅ SBOM generation completed`);

//       if (!fs.existsSync(fullOutputPath)) {
//         this.logError(`❌ Output file not created: ${fullOutputPath}`);
//         throw new Error('CDXgen did not generate SBOM output file');
//       }

//       return fullOutputPath;
//     } catch (error) {
//       this.logError(`❌ CDXgen SBOM generation failed: ${error.message}`);
//       throw error;
//     }
//   }

//   /**
//    * Required by orchestrator
//    */
//   async scan(config) {
//     try {
//       const targetDir = config.scanTarget || '.';

//       const sbomPath = await this.generateSBOM(targetDir);
//       this.log(`📦 SBOM generated: ${sbomPath}`);
    
//       // Ensure Trivy is installed
//       if (!trivyScanner.binaryPath) {
//         this.log('🔧 Trivy not found, installing Trivy scanner in sbom...');
//         await trivyScanner.install();
//       }
//       this.trivyBinaryPath = trivyScanner.binaryPath;

//       const trivyArgs = [
//         'sbom',
//         '--format', 'json',
//         '--quiet',
//         sbomPath
//       ];

//       const command = `${this.trivyBinaryPath} ${trivyArgs.join(' ')}`;
//       this.log(`🛠️ Using Trivy binary at: ${this.trivyBinaryPath}`);
//       this.logDebug(`🧩 Running command: ${command}`);

//       let stdoutData = '';

//       try {
//         const { stdout } = await execAsync(command, {
//           maxBuffer: 10 * 1024 * 1024, // 10MB buffer
//           encoding: 'utf8'
//         });
//         stdoutData = stdout;
//       } catch (error) {
//         // Trivy might return non-zero exit code even with valid results
//         stdoutData = error.stdout || '';
//         if (!stdoutData) {
//           throw error;
//         }
//       }

//       if (stdoutData.trim() === '') {
//         this.logWarning('⚠️  No vulnerabilities found');
//         return {
//           total: 0,
//           critical: 0,
//           high: 0,
//           medium: 0,
//           low: 0,
//           vulnerabilities: [],
//           sbomPath
//         };
//       }

//       const data = JSON.parse(stdoutData);
//       const vulns = (data.Results || []).flatMap(r => r.Vulnerabilities || []).filter(v => v);

//       const countBySeverity = {
//         CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0
//       };

//       vulns.forEach(vuln => {
//         const sev = (vuln.Severity || 'UNKNOWN').toUpperCase();
//         if (countBySeverity[sev] !== undefined) {
//           countBySeverity[sev]++;
//         }
//       });

//       this.log(`📊 Vulnerability Summary:`);
//       this.log(`   CRITICAL: ${countBySeverity.CRITICAL}`);
//       this.log(`   HIGH:     ${countBySeverity.HIGH}`);
//       this.log(`   MEDIUM:   ${countBySeverity.MEDIUM}`);
//       this.log(`   LOW:      ${countBySeverity.LOW}`);
//       this.log(`   TOTAL:    ${vulns.length}`);

//       return {
//         total: vulns.length,
//         critical: countBySeverity.CRITICAL,
//         high: countBySeverity.HIGH,
//         medium: countBySeverity.MEDIUM,
//         low: countBySeverity.LOW,
//         vulnerabilities: vulns,
//         sbomPath
//       };

//     } catch (error) {
//       this.logError(`❌ Scan failed: ${error.message}`);
//       this.log('➡️ Falling back to Trivy scanner...');

//       // Fallback: call trivy.js scanner directly
//       return await trivyScanner.scan(config);
//     }
//   }

// }

// module.exports = new CdxgenScanner();