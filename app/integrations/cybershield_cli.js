/**
 * OmniFetch <-> CyberShield Safe Node.js CLI Gateway
 * 
 * Invokes CyberShield's real offline JavaScript engines strictly without modifying
 * or copying files from CyberShield:
 * 1. pe_heuristics.js (Zero-dependency PE parser & Shannon entropy)
 * 2. clamav_bridge.js (Microsoft-signed MpCmdRun.exe -DisableRemediation)
 * 3. quarantine.js (AES-256-GCM + Zlib reversible vault)
 */

const path = require('path');
const fs = require('fs');

const CYBERSHIELD_ROOT = process.env.CYBERSHIELD_ROOT || 'C:\\Users\\shrey\\Desktop\\CyberShield';
const PE_HEURISTICS_PATH = path.join(CYBERSHIELD_ROOT, 'core', 'pe_heuristics.js');
const CLAMAV_BRIDGE_PATH = path.join(CYBERSHIELD_ROOT, 'core', 'clamav_bridge.js');
const QUARANTINE_PATH = path.join(CYBERSHIELD_ROOT, 'core', 'quarantine.js');
const DB_MODULE_PATH = path.join(CYBERSHIELD_ROOT, 'core', 'db.js');

async function handleScan(filePath) {
  if (!fs.existsSync(filePath)) {
    console.log(JSON.stringify({ error: `File not found: ${filePath}` }));
    process.exit(1);
  }

  const results = {
    filePath: path.resolve(filePath),
    fileName: path.basename(filePath),
    verdict: 'ALLOW_CLEAN',
    severity: 'CLEAN',
    threatName: null,
    riskScore: 0,
    details: 'Clean (No threat signatures detected)',
    detections: []
  };

  // 1. Run CyberShield PE Heuristics
  try {
    if (fs.existsSync(PE_HEURISTICS_PATH)) {
      const { analyzeFile } = require(PE_HEURISTICS_PATH);
      const stats = fs.statSync(filePath);
      let buffer = null;

      // For PE analysis, read header + first 2MB or entire file if <= 15MB
      if (stats.size <= 15 * 1024 * 1024) {
        buffer = fs.readFileSync(filePath);
      } else {
        const fd = fs.openSync(filePath, 'r');
        const readLen = Math.min(stats.size, 2 * 1024 * 1024);
        buffer = Buffer.alloc(readLen);
        fs.readSync(fd, buffer, 0, readLen, 0);
        fs.closeSync(fd);
      }

      const heuristic = analyzeFile(filePath, buffer, { fileSize: stats.size });
      if (heuristic && heuristic.verdict !== 'CLEAN') {
        results.detections.push({
          source: 'PE_Heuristics',
          threatName: heuristic.threatName,
          severity: heuristic.severity,
          verdict: heuristic.verdict,
          details: heuristic.details,
          riskScore: heuristic.riskScore || (heuristic.severity === 'CRITICAL' ? 10 : 3)
        });
      }
    }
  } catch (err) {
    // Non-fatal, continue to Defender pass
  }

  // 2. Run Signed Defender CLI Pass (Strictly -DisableRemediation)
  try {
    if (fs.existsSync(CLAMAV_BRIDGE_PATH)) {
      const ClamAVBridge = require(CLAMAV_BRIDGE_PATH);
      const bridge = new ClamAVBridge();
      const status = bridge.getStatus();
      if (status.available && status.exePath) {
        const scanRes = await bridge.scanPath(filePath);
        if (scanRes && scanRes.detections && scanRes.detections.length > 0) {
          for (const det of scanRes.detections) {
            results.detections.push({
              source: 'DefenderCLI_ReadOnly',
              threatName: det.threatName,
              severity: det.severity,
              verdict: det.verdict,
              details: det.details,
              riskScore: det.riskScore || (det.severity === 'CRITICAL' ? 9 : 3)
            });
          }
        }
      }
    }
  } catch (err) {
    // Non-fatal
  }

  // 3. Evaluate combined 3-Tier Severity Filter
  const criticals = results.detections.filter(d => d.severity === 'CRITICAL');
  const warnings = results.detections.filter(d => d.severity === 'LOW');

  if (criticals.length > 0) {
    results.verdict = 'BLOCK_CRITICAL';
    results.severity = 'CRITICAL';
    results.threatName = criticals[0].threatName;
    results.riskScore = Math.max(...criticals.map(c => c.riskScore || 9));
    results.details = criticals.map(c => c.details).join('; ');
  } else if (warnings.length > 0) {
    results.verdict = 'ALLOW_WARNING';
    results.severity = 'LOW';
    results.threatName = warnings[0].threatName;
    results.riskScore = Math.max(...warnings.map(w => w.riskScore || 3));
    results.details = warnings.map(w => w.details).join('; ');
  }

  console.log(JSON.stringify(results));
}

async function handleQuarantine(filePath, threatName, details) {
  if (!fs.existsSync(filePath)) {
    console.log(JSON.stringify({ error: `File not found: ${filePath}` }));
    process.exit(1);
  }

  try {
    const { getThreatDatabase } = require(DB_MODULE_PATH);
    const QuarantineVault = require(QUARANTINE_PATH);
    const db = getThreatDatabase();
    const vault = new QuarantineVault(undefined, db);

    const record = vault.quarantineFile(filePath, threatName || 'Threat.Generic', {
      sourceApp: 'OmniFetch Security Gate',
      details: details || 'Isolated via OmniFetch post-download verification'
    });

    console.log(JSON.stringify({
      success: true,
      quarantined: true,
      vaultRecordId: record.id,
      vaultPath: record.vaultPath,
      originalPath: record.originalPath
    }));
  } catch (err) {
    console.log(JSON.stringify({
      success: false,
      error: err.message
    }));
    process.exit(1);
  }
}

async function handleMetadataCheck(url, filename) {
  const ext = path.extname(filename || '').toLowerCase();
  const lowerName = (filename || '').toLowerCase();

  // Dangerous / Camouflaged Extension Rules
  const deceptivePatterns = [
    /\.(pdf|docx?|xlsx?|jpg|png|mp4|mkv|mp3|avi|txt)\.(exe|scr|bat|cmd|vbs|js|ps1|hta|wsf)$/i,
    /\.(exe|scr|bat|cmd|vbs|hta|wsf)$/i
  ];

  for (const pat of deceptivePatterns) {
    if (pat.test(lowerName)) {
      const isDoubleExt = /\.[a-z0-9]+\.(exe|scr|bat|cmd|vbs)$/i.test(lowerName);
      if (isDoubleExt) {
        console.log(JSON.stringify({
          verdict: 'BLOCK_CRITICAL',
          severity: 'CRITICAL',
          threatName: 'Exploit.DoubleExtension',
          details: `Deceptive double extension detected: ${filename}`
        }));
        return;
      } else {
        console.log(JSON.stringify({
          verdict: 'ALLOW_WARNING',
          severity: 'LOW',
          threatName: 'PotentiallyUnwanted.Executable',
          details: `Executable or script download: ${filename}`
        }));
        return;
      }
    }
  }

  console.log(JSON.stringify({
    verdict: 'ALLOW_CLEAN',
    severity: 'CLEAN',
    threatName: null,
    details: 'Metadata check passed'
  }));
}

async function main() {
  const [,, cmd, arg1, arg2, arg3] = process.argv;

  if (cmd === 'scan') {
    await handleScan(arg1);
  } else if (cmd === 'quarantine') {
    await handleQuarantine(arg1, arg2, arg3);
  } else if (cmd === 'check-metadata') {
    await handleMetadataCheck(arg1, arg2);
  } else {
    console.log(JSON.stringify({ error: `Unknown command: ${cmd}` }));
    process.exit(1);
  }
}

main().catch(err => {
  console.log(JSON.stringify({ error: err.message }));
  process.exit(1);
});
