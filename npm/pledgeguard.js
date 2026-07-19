#!/usr/bin/env node
// pledgeguard.js — thin wrapper that spawns the platform-specific binary.

const { spawn } = require("child_process");
const path = require("path");

const isWindows = process.platform === "win32";
const binName = isWindows ? "pledgeguard.exe" : "pledgeguard";
const binPath = path.join(__dirname, "bin", binName);

const child = spawn(binPath, process.argv.slice(2), {
  stdio: "inherit",
  windowsHide: false,
});

child.on("error", (err) => {
  if (err.code === "ENOENT") {
    console.error(
      "pledgeguard: binary not found. The postinstall script may have failed.\n" +
        "Try running `npm rebuild pledgeguard` or install from source:\n" +
        "https://github.com/pledgeandgrow/pledgeguard/releases"
    );
  } else {
    console.error(`pledgeguard: ${err.message}`);
  }
  process.exit(1);
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
  } else {
    process.exit(code ?? 1);
  }
});
