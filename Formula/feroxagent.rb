class Feroxagent < Formula
  desc "AI-powered content discovery tool for penetration testing"
  homepage "https://github.com/kylejryan/feroxagent"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/kylejryan/feroxagent/releases/download/v0.1.0/aarch64-macos-feroxagent.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AFTER_RELEASE"
    end
    on_intel do
      url "https://github.com/kylejryan/feroxagent/releases/download/v0.1.0/x86_64-macos-feroxagent.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AFTER_RELEASE"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/kylejryan/feroxagent/releases/download/v0.1.0/aarch64-linux-feroxagent.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AFTER_RELEASE"
    end
    on_intel do
      url "https://github.com/kylejryan/feroxagent/releases/download/v0.1.0/x86_64-linux-feroxagent.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AFTER_RELEASE"
    end
  end

  def install
    bin.install "feroxagent"
  end

  test do
    assert_match "feroxagent", shell_output("#{bin}/feroxagent --version")
  end
end
