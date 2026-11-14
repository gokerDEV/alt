class Alt < Formula
  desc "Local-first HTTPS proxy and signed name resolver for .alt private DNS namespaces"
  homepage "https://github.com/goker/alt"
  url "https://github.com/goker/alt/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "REPLACE_WITH_RELEASE_TARBALL_SHA256"
  license "Apache-2.0"

  depends_on "go" => :build

  def install
    ldflags = %W[
      -s -w
      -X main.Version=#{version}
      -X main.Commit=#{tap.user || "homebrew"}
      -X main.BuildDate=#{time.iso8601}
    ]
    system "go", "build", *std_go_args(ldflags:), "./cmd/alt"
    generate_completions_from_executable(bin/"alt", "completion")
  end

  def caveats
    <<~EOS
      To enable direct browser access to https://<name>.alt on port 443
      (coexisting safely alongside Caddy and other *:443 servers via 127.0.0.2):
        sudo #{opt_bin}/alt setup

      To remove macOS system integration cleanly at any time:
        sudo #{opt_bin}/alt uninstall
    EOS
  end

  test do
    output = shell_output("#{bin}/alt version --json")
    assert_match version.to_s, output
  end
end
