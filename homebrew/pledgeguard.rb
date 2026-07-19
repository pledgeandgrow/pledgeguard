class Pledgeguard < Formula
  desc "Rust-native secret scanner — a TruffleHog/Gitleaks alternative"
  homepage "https://github.com/pledgeandgrow/pledgeguard"
  url "https://github.com/pledgeandgrow/pledgeguard/releases/download/v0.1.1/pledgeguard-aarch64-apple-darwin.tar.gz"
  version "0.1.1"
  sha256 ""
  license "MIT"

  on_intel do
    url "https://github.com/pledgeandgrow/pledgeguard/releases/download/v0.1.1/pledgeguard-x86_64-apple-darwin.tar.gz"
    sha256 ""
  end

  def install
    bin.install "pledgeguard"
  end

  test do
    assert_match "pledgeguard", shell_output("#{bin}/pledgeguard --version")
  end
end
