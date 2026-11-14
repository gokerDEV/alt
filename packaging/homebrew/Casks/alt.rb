cask "alt" do
  version "0.2.0"
  sha256 "REPLACE_WITH_MACOS_PKG_SHA256"

  url "https://github.com/goker/alt/releases/download/v#{version}/alt-#{version}-darwin-universal.pkg"
  name "ALT"
  desc "Local-first HTTPS proxy and signed name resolver for .alt domains"
  homepage "https://github.com/goker/alt"

  depends_on macos: ">= :monterey"

  pkg "alt-#{version}-darwin-universal.pkg"

  uninstall script: {
              executable: "/Library/Application Support/alt/uninstall.sh",
              sudo:       true,
            },
            pkgutil: "dev.alt.pkg"

  zap trash: [
    "~/Library/Application Support/alt",
  ]
end
