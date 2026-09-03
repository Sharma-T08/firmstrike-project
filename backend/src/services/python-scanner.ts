import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const PYTHON_SCANNER_URL =
  process.env.PYTHON_SCANNER_URL ||
  "http://127.0.0.1:8010";

export type PythonScannerResult = {
  scanId: number;
  firmwareId: number;
  status: string;

  firmware: {
    name: string;
    size: number;
    sha256: string;
    format: string;
  };

  metadata: {
    architecture: string;
    vendor: string | null;
    version: string | null;
    components: Array<
      string | {
        name: string;
        version?: string;
        type?: string;
        path?: string;
        source?: string;
      }
    >;
  };

  extraction: {
    path: string;
    filesExtracted: number;
    binwalk: {
      available: boolean;
      success: boolean;
      message: string;
    };
  };

  files: Array<{
    path: string;
    type: string;
    size: number;
    permissions: string | null;
    isSuspicious: boolean;
  }>;

  strings: {
    count: number;
    sample: string[];
  };

  staticAnalysis: {
    secrets: Array<{
      type: string;
      value: string;
      file: string;
      line: number;
      severity: string;
    }>;

    dangerous: Array<{
      name: string;
      file: string;
      line: number;
      risk: string;
      description: string;
    }>;

    vulnerabilities: Array<{
      type: string;
      severity: string;
      description: string;
      affectedFile?: string;
      file?: string;
      line?: number;
    }>;
  };

  malware: Array<{
    sha256: string;
    fileName: string;
    threatScore: number;
    virusTotalResult: string;
    isMalicious: boolean;
    detectionCount: number;
    totalEngines: number;
    indicators?: string[];
  }>;

  sbom: {
    components: Array<{
      name: string;
      version: string;
      type: string;
      path: string;
      source: string;
    }>;
  };
};

export type RunPythonScannerOptions = {
  firmwareId: number;
  scanId: number;
  filePath: string;
  extractPath: string;
};

function normalizePath(value: string): string {
  return path.resolve(value);
}

function processComponents(result: PythonScannerResult) {
  const sbomComponents = result.sbom?.components ?? [];
  const metaRaw = result.metadata?.components ?? [];

  const metaParsed = metaRaw.map((item) => {
    if (typeof item === "object" && item !== null) {
      return {
        name: item.name,
        version: item.version ?? "unknown",
        type: item.type ?? "component",
        path: item.path ?? "/firmware.bin",
        source: item.source ?? "python-scanner-metadata",
      };
    }

    const str = String(item).trim();
    const verMatch = str.match(/(\d+\.\d+(?:\.\d+)?)/);
    const name = str.split(/\s+/)[0] || str;

    return {
      name,
      version: verMatch ? verMatch[1] : "unknown",
      type: "component",
      path: "/firmware.bin",
      source: "python-scanner-metadata",
    };
  });

  const map = new Map<string, { name: string; version: string; type: string; path: string; source: string }>();

  for (const c of [...sbomComponents, ...metaParsed]) {
    const key = `${c.name.toLowerCase()}:${c.version}`;
    if (!map.has(key)) {
      map.set(key, c);
    }
  }

  return Array.from(map.values());
}

async function runDirectPythonScanner(
  filePath: string,
  extractPath: string,
  firmwareId: number,
  scanId: number,
): Promise<PythonScannerResult> {
  const pythonDir = path.resolve(process.cwd(), "python-scanner");

  const pythonScript = `
import json, sys
sys.path.append('.')
from scanner import scan_firmware

res = scan_firmware(${JSON.stringify(filePath)}, ${JSON.stringify(extractPath)}, ${firmwareId}, ${scanId})
print(json.dumps(res))
`;

  const { stdout } = await execFileAsync("python", ["-c", pythonScript], {
    cwd: pythonDir,
    maxBuffer: 50 * 1024 * 1024,
  });

  return JSON.parse(stdout) as PythonScannerResult;
}

export async function runPythonScanner(
  options: RunPythonScannerOptions,
): Promise<{
  architecture: string;
  vendor: string | null;
  version: string | null;
  components: Array<{
    name: string;
    version: string;
    type: string;
    path: string;
    source: string;
  }>;
  files: PythonScannerResult["files"];
  staticAnalysis: PythonScannerResult["staticAnalysis"];
  malware: PythonScannerResult["malware"];
  extraction: PythonScannerResult["extraction"];
  sbom: PythonScannerResult["sbom"];
}> {
  const filePath = normalizePath(options.filePath);
  const extractPath = normalizePath(options.extractPath);

  console.log("");
  console.log("========================================");
  console.log("       PYTHON SCANNER REQUEST");
  console.log("========================================");
  console.log("Firmware ID :", options.firmwareId);
  console.log("Scan ID     :", options.scanId);
  console.log("File path   :", filePath);
  console.log("Extract path:", extractPath);
  console.log("Scanner URL :", PYTHON_SCANNER_URL);
  console.log("========================================");
  console.log("");

  let result: PythonScannerResult;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 60_000);

    try {
      const response = await fetch(`${PYTHON_SCANNER_URL}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          firmwareId: options.firmwareId,
          scanId: options.scanId,
          filePath,
          extractPath,
        }),
        signal: controller.signal,
      });

      clearTimeout(timeout);

      const raw = await response.text();
      if (!response.ok) {
        throw new Error(`Python scanner HTTP ${response.status}: ${raw}`);
      }
      result = JSON.parse(raw);
    } catch (httpError) {
      clearTimeout(timeout);
      console.log("[Python Scanner] HTTP service not available on port 8010. Running scanner module directly via Python...");
      result = await runDirectPythonScanner(filePath, extractPath, options.firmwareId, options.scanId);
    }

    if (!result.metadata) {
      throw new Error("Python scanner response is missing metadata");
    }

    const processedComponents = processComponents(result);

    console.log("");
    console.log("========================================");
    console.log("       PYTHON SCANNER RESULT");
    console.log("========================================");
    console.log("Architecture :", result.metadata.architecture);
    console.log("Vendor       :", result.metadata.vendor ?? "UNKNOWN");
    console.log("Version      :", result.metadata.version ?? "UNKNOWN");
    console.log("Components   :", processedComponents.length);
    console.log("Files        :", result.files?.length ?? 0);
    console.log("Secrets      :", result.staticAnalysis?.secrets?.length ?? 0);
    console.log("Dangerous    :", result.staticAnalysis?.dangerous?.length ?? 0);
    console.log("Malware      :", result.malware?.length ?? 0);
    console.log("========================================");
    console.log("");

    return {
      architecture: result.metadata.architecture || "UNKNOWN",
      vendor: result.metadata.vendor ?? null,
      version: result.metadata.version ?? null,
      components: processedComponents,
      files: result.files ?? [],
      staticAnalysis: result.staticAnalysis ?? {
        secrets: [],
        dangerous: [],
        vulnerabilities: [],
      },
      malware: result.malware ?? [],
      extraction: result.extraction,
      sbom: {
        components: processedComponents,
      },
    };
  } catch (error) {
    console.error("[Python Scanner Error]", error);
    throw error;
  }
}