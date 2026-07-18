// generate-platform-packages.js — generates the platform-specific npm
// packages that contain the prebuilt pledgeguard binary. Run this after
// building binaries for each platform.
//
// Usage: node generate-platform-packages.js
//
// This creates packages in npm/platform-packages/ with the following naming:
//   @pledgeandgrow/pledgeguard-{platform}-{arch}
//
// Each package has a postinstall that copies the binary into the parent
// package's bin/ directory.

const fs = require("fs");
const path = require("path");

const PLATFORMS = [
  { name: "darwin-arm64", dir: "darwin-arm64" },
  { name: "darwin-x64", dir: "darwin-x64" },
  { name: "linux-arm64", dir: "linux-arm64" },
  { name: "linux-x64", dir: "linux-x64" },
  { name: "win32-x64", dir: "win32-x64" },
];

const outDir = path.join(__dirname, "platform-packages");
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

for (const p of PLATFORMS) {
  const pkgDir = path.join(outDir, p.dir);
  if (!fs.existsSync(pkgDir)) fs.mkdirSync(pkgDir, { recursive: true });

  const pkgJson = {
    name: `@pledgeandgrow/pledgeguard-${p.name}`,
    version: "0.1.0",
    description: `PledgeGuard binary for ${p.name}`,
    license: "MIT",
    os: [p.name.split("-")[0]],
    cpu: [p.name.split("-")[1]],
    files: ["bin/"],
  };

  fs.writeFileSync(
    path.join(pkgDir, "package.json"),
    JSON.stringify(pkgJson, null, 2) + "\n"
  );

  // Create a placeholder bin directory (real binary goes here during release)
  const binDir = path.join(pkgDir, "bin");
  if (!fs.existsSync(binDir)) fs.mkdirSync(binDir);

  console.log(`Generated ${p.dir}/package.json`);
}

console.log("\nDone. Copy the built binaries into each platform-packages/*/bin/ directory.");
