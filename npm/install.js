// install.js — resolves the platform-specific pledgeguard binary from
// optional dependencies and symlinks/copies it into bin/.
// If no platform package is installed (e.g. dev mode), falls back to
// downloading from GitHub Releases.

const fs = require("fs");
const path = require("path");
const https = require("https");
const { execSync } = require("child_process");

const PLATFORM_PACKAGES = {
  darwin: {
    arm64: "@pledgeandgrow/pledgeguard-darwin-arm64",
    x64: "@pledgeandgrow/pledgeguard-darwin-x64",
  },
  linux: {
    arm64: "@pledgeandgrow/pledgeguard-linux-arm64",
    x64: "@pledgeandgrow/pledgeguard-linux-x64",
  },
  win32: {
    x64: "@pledgeandgrow/pledgeguard-win32-x64",
  },
};

const GITHUB_RELEASES = {
  darwin: {
    arm64: "pledgeguard-aarch64-apple-darwin.tar.gz",
    x64: "pledgeguard-x86_64-apple-darwin.tar.gz",
  },
  linux: {
    arm64: "pledgeguard-aarch64-unknown-linux-gnu.tar.gz",
    x64: "pledgeguard-x86_64-unknown-linux-gnu.tar.gz",
  },
  win32: {
    x64: "pledgeguard-x86_64-pc-windows-msvc.zip",
  },
};

const platform = process.platform;
const arch = process.arch;
const isWindows = platform === "win32";
const binName = isWindows ? "pledgeguard.exe" : "pledgeguard";
const binDir = path.join(__dirname, "bin");
const binPath = path.join(binDir, binName);

function ensureBinDir() {
  if (!fs.existsSync(binDir)) {
    fs.mkdirSync(binDir, { recursive: true });
  }
}

function tryPlatformPackage() {
  const pkg = PLATFORM_PACKAGES[platform]?.[arch];
  if (!pkg) return false;

  try {
    const pkgPath = require.resolve(pkg);
    const pkgBin = path.join(path.dirname(pkgPath), "bin", binName);
    if (fs.existsSync(pkgBin)) {
      ensureBinDir();
      if (isWindows) {
        fs.copyFileSync(pkgBin, binPath);
      } else {
        // Try symlink first, fall back to copy
        try {
          fs.symlinkSync(pkgBin, binPath);
        } catch {
          fs.copyFileSync(pkgBin, binPath);
        }
        fs.chmodSync(binPath, 0o755);
      }
      console.log(`pledgeguard: installed from ${pkg}`);
      return true;
    }
  } catch {
    // Package not installed
  }
  return false;
}

function downloadAndExtract() {
  const asset = GITHUB_RELEASES[platform]?.[arch];
  if (!asset) {
    console.error(
      `pledgeguard: unsupported platform ${platform}-${arch}. Please build from source: https://github.com/pledgeandgrow/pledgeguard`
    );
    process.exit(1);
  }

  const version = require("./package.json").version;
  const url = `https://github.com/pledgeandgrow/pledgeguard/releases/download/v${version}/${asset}`;

  console.log(`pledgeguard: downloading ${asset} from GitHub Releases...`);

  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        if (res.statusCode === 302 || res.statusCode === 301) {
          // Follow redirect
          https.get(res.headers.location, (res2) => {
            handleDownload(res2, asset, resolve, reject);
          });
        } else if (res.statusCode === 200) {
          handleDownload(res, asset, resolve, reject);
        } else {
          reject(
            new Error(
              `pledgeguard: download failed (HTTP ${res.statusCode}). ` +
                `You may need to build from source: https://github.com/pledgeandgrow/pledgeguard`
            )
          );
        }
      })
      .on("error", reject);
  });
}

function handleDownload(res, asset, resolve, reject) {
  ensureBinDir();
  const tmpPath = path.join(binDir, asset);

  const stream = fs.createWriteStream(tmpPath);
  res.pipe(stream);
  stream.on("finish", () => {
    stream.close(() => {
      try {
        if (asset.endsWith(".tar.gz")) {
          execSync(`tar xzf "${tmpPath}" -C "${binDir}"`, { stdio: "inherit" });
        } else if (asset.endsWith(".zip")) {
          execSync(`powershell Expand-Archive -Path "${tmpPath}" -DestinationPath "${binDir}" -Force`, {
            stdio: "inherit",
          });
        }
        fs.unlinkSync(tmpPath);

        // The archive contains a 'pledgeguard' binary at root
        const extractedPath = path.join(binDir, binName);
        if (fs.existsSync(extractedPath)) {
          if (!isWindows) fs.chmodSync(extractedPath, 0o755);
          console.log(`pledgeguard: installed from GitHub Releases`);
          resolve();
        } else {
          reject(new Error(`pledgeguard: binary not found after extraction`));
        }
      } catch (e) {
        reject(e);
      }
    });
  });
  stream.on("error", reject);
}

async function main() {
  // Try platform-specific package first
  if (tryPlatformPackage()) {
    return;
  }

  // Fall back to downloading from GitHub Releases
  try {
    await downloadAndExtract();
  } catch (e) {
    console.error(`pledgeguard: ${e.message}`);
    process.exit(1);
  }
}

main();
