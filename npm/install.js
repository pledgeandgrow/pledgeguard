// install.js — downloads the platform-specific pledgeguard binary
// from GitHub Releases on npm install. Single package, no platform deps.

const fs = require("fs");
const path = require("path");
const https = require("https");
const { execSync } = require("child_process");

const ASSETS = {
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

const asset = ASSETS[platform]?.[arch];
if (!asset) {
  console.error(
    `pledgeguard: unsupported platform ${platform}-${arch}. ` +
      `Build from source: https://github.com/pledgeandgrow/pledgeguard`
  );
  process.exit(1);
}

const version = require("./package.json").version;
const url = `https://github.com/pledgeandgrow/pledgeguard/releases/download/v${version}/${asset}`;

console.log(`pledgeguard: downloading ${asset}...`);

function followRedirects(url, callback) {
  https.get(url, (res) => {
    if (res.statusCode === 302 || res.statusCode === 301) {
      followRedirects(res.headers.location, callback);
    } else if (res.statusCode === 200) {
      callback(res);
    } else {
      console.error(
        `pledgeguard: download failed (HTTP ${res.statusCode}). ` +
          `The v${version} release may not exist yet. ` +
          `Build from source: https://github.com/pledgeandgrow/pledgeguard`
      );
      process.exit(1);
    }
  }).on("error", (e) => {
    console.error(`pledgeguard: ${e.message}`);
    process.exit(1);
  });
}

if (!fs.existsSync(binDir)) fs.mkdirSync(binDir, { recursive: true });

followRedirects(url, (res) => {
  const tmpPath = path.join(binDir, asset);
  const stream = fs.createWriteStream(tmpPath);
  res.pipe(stream);
  stream.on("finish", () => {
    stream.close(() => {
      try {
        if (asset.endsWith(".tar.gz")) {
          execSync(`tar xzf "${tmpPath}" -C "${binDir}"`, { stdio: "inherit" });
        } else if (asset.endsWith(".zip")) {
          execSync(
            `powershell Expand-Archive -Path "${tmpPath}" -DestinationPath "${binDir}" -Force`,
            { stdio: "inherit" }
          );
        }
        fs.unlinkSync(tmpPath);

        if (fs.existsSync(binPath)) {
          if (!isWindows) fs.chmodSync(binPath, 0o755);
          console.log("pledgeguard: installed successfully.");
        } else {
          console.error("pledgeguard: binary not found after extraction.");
          process.exit(1);
        }
      } catch (e) {
        console.error(`pledgeguard: ${e.message}`);
        process.exit(1);
      }
    });
  });
  stream.on("error", (e) => {
    console.error(`pledgeguard: ${e.message}`);
    process.exit(1);
  });
});
