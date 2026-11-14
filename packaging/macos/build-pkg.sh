#!/bin/sh
# Builds a distributable macOS .pkg installer (universal arm64+amd64 or single-arch),
# tar.gz binary archive, shell completions, and SHA256SUMS.
# Supports optional Developer ID signing and Apple Notary Service stapling when env vars are set:
#   APPLE_DEVELOPER_ID_APP       ("Developer ID Application: ...")
#   APPLE_DEVELOPER_ID_INSTALLER ("Developer ID Installer: ...")
#   APPLE_NOTARY_PROFILE         (keychain profile name) OR APPLE_ID + APPLE_TEAM_ID + APPLE_APP_SPECIFIC_PASSWORD
set -eu
export COPYFILE_DISABLE=1

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

VERSION="${VERSION:-0.2.0}"
VERSION_CLEAN="${VERSION#v}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo dev)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"
ARCH_MODE="${ARCH_MODE:-universal}" # "universal", "arm64", or "amd64"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/dist}"

LDFLAGS="-s -w -X main.Version=${VERSION_CLEAN} -X main.Commit=${COMMIT} -X main.BuildDate=${BUILD_DATE}"

STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/alt-pkg-stage.XXXXXX")"
trap 'rm -rf "$STAGE_DIR"' EXIT

PAYLOAD_ROOT="${STAGE_DIR}/payload"
SCRIPTS_DIR="${STAGE_DIR}/scripts"
mkdir -p "${PAYLOAD_ROOT}/usr/local/bin" \
         "${PAYLOAD_ROOT}/usr/local/share/zsh/site-functions" \
         "${PAYLOAD_ROOT}/usr/local/share/bash-completion/completions" \
         "${PAYLOAD_ROOT}/usr/local/share/fish/vendor_completions.d" \
         "${PAYLOAD_ROOT}/Library/Application Support/alt" \
         "${SCRIPTS_DIR}" \
         "${OUT_DIR}"

echo "==> Building alt ${VERSION_CLEAN} (${ARCH_MODE}, commit=${COMMIT})"
HOST_ARCH="$(go env GOARCH)"

if [ "$ARCH_MODE" = "universal" ]; then
  CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "$LDFLAGS" -o "${STAGE_DIR}/alt-arm64" ./cmd/alt
  CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o "${STAGE_DIR}/alt-amd64" ./cmd/alt
  /usr/bin/lipo -create -output "${PAYLOAD_ROOT}/usr/local/bin/alt" "${STAGE_DIR}/alt-arm64" "${STAGE_DIR}/alt-amd64"
  NATIVE_BIN="${STAGE_DIR}/alt-${HOST_ARCH}"
else
  CGO_ENABLED=0 GOOS=darwin GOARCH="${ARCH_MODE}" go build -trimpath -ldflags "$LDFLAGS" -o "${PAYLOAD_ROOT}/usr/local/bin/alt" ./cmd/alt
  NATIVE_BIN="${PAYLOAD_ROOT}/usr/local/bin/alt"
fi

chmod 0755 "${PAYLOAD_ROOT}/usr/local/bin/alt"

# Generate shell completions using host-compatible binary
"$NATIVE_BIN" completion zsh > "${PAYLOAD_ROOT}/usr/local/share/zsh/site-functions/_alt"
"$NATIVE_BIN" completion bash > "${PAYLOAD_ROOT}/usr/local/share/bash-completion/completions/alt"
"$NATIVE_BIN" completion fish > "${PAYLOAD_ROOT}/usr/local/share/fish/vendor_completions.d/alt.fish"
chmod 0644 "${PAYLOAD_ROOT}/usr/local/share/zsh/site-functions/_alt" \
           "${PAYLOAD_ROOT}/usr/local/share/bash-completion/completions/alt" \
           "${PAYLOAD_ROOT}/usr/local/share/fish/vendor_completions.d/alt.fish"

cp "${REPO_ROOT}/packaging/macos/uninstall.sh" "${PAYLOAD_ROOT}/Library/Application Support/alt/uninstall.sh"
chmod 0755 "${PAYLOAD_ROOT}/Library/Application Support/alt/uninstall.sh"

cp "${REPO_ROOT}/packaging/macos/scripts/preinstall" "${SCRIPTS_DIR}/preinstall"
cp "${REPO_ROOT}/packaging/macos/scripts/postinstall" "${SCRIPTS_DIR}/postinstall"
chmod 0755 "${SCRIPTS_DIR}/preinstall" "${SCRIPTS_DIR}/postinstall"
/usr/bin/xattr -cr "${PAYLOAD_ROOT}" "${SCRIPTS_DIR}" 2>/dev/null || true

# Sign executable with hardened runtime if Developer ID Application identity is configured
if [ -n "${APPLE_DEVELOPER_ID_APP:-}" ]; then
  echo "==> Signing binary with ${APPLE_DEVELOPER_ID_APP}"
  /usr/bin/codesign --force --options runtime --timestamp --sign "${APPLE_DEVELOPER_ID_APP}" "${PAYLOAD_ROOT}/usr/local/bin/alt"
  /usr/bin/codesign --verify --verbose "${PAYLOAD_ROOT}/usr/local/bin/alt"
fi

COMPONENT_PKG="${STAGE_DIR}/alt-component.pkg"
DIST_XML="${STAGE_DIR}/Distribution.xml"
PKG_NAME="alt-${VERSION_CLEAN}-darwin-${ARCH_MODE}.pkg"
FINAL_PKG="${OUT_DIR}/${PKG_NAME}"
TAR_NAME="alt-${VERSION_CLEAN}-darwin-${ARCH_MODE}.tar.gz"
FINAL_TAR="${OUT_DIR}/${TAR_NAME}"

/usr/bin/pkgbuild \
  --root "${PAYLOAD_ROOT}" \
  --scripts "${SCRIPTS_DIR}" \
  --identifier "dev.alt.pkg" \
  --version "${VERSION_CLEAN}" \
  --install-location "/" \
  "${COMPONENT_PKG}" >/dev/null

cat > "${DIST_XML}" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>ALT (.alt Local HTTPS &amp; Signed Namespace Resolver)</title>
    <options customize="never" require-scripts="true" hostArchitectures="arm64,x86_64"/>
    <volume-check>
        <allowed-os-versions>
            <os-version min="12.0"/>
        </allowed-os-versions>
    </volume-check>
    <choices-outline>
        <line choice="default">
            <line choice="dev.alt.pkg"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="dev.alt.pkg" visible="false">
        <pkg-ref id="dev.alt.pkg"/>
    </choice>
    <pkg-ref id="dev.alt.pkg" version="${VERSION_CLEAN}" onConclusion="none">alt-component.pkg</pkg-ref>
</installer-gui-script>
EOF

if [ -n "${APPLE_DEVELOPER_ID_INSTALLER:-}" ]; then
  echo "==> Building signed distribution package with ${APPLE_DEVELOPER_ID_INSTALLER}"
  /usr/bin/productbuild \
    --distribution "${DIST_XML}" \
    --package-path "${STAGE_DIR}" \
    --sign "${APPLE_DEVELOPER_ID_INSTALLER}" \
    "${FINAL_PKG}" >/dev/null
else
  /usr/bin/productbuild \
    --distribution "${DIST_XML}" \
    --package-path "${STAGE_DIR}" \
    "${FINAL_PKG}" >/dev/null
fi

# Notarize and staple when Apple Notary credentials are provided
if [ -n "${APPLE_NOTARY_PROFILE:-}" ]; then
  echo "==> Submitting ${PKG_NAME} for Apple notarization (profile=${APPLE_NOTARY_PROFILE})"
  xcrun notarytool submit "${FINAL_PKG}" --keychain-profile "${APPLE_NOTARY_PROFILE}" --wait
  xcrun stapler staple "${FINAL_PKG}"
elif [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] && [ -n "${APPLE_APP_SPECIFIC_PASSWORD:-}" ]; then
  echo "==> Submitting ${PKG_NAME} for Apple notarization (team=${APPLE_TEAM_ID})"
  xcrun notarytool submit "${FINAL_PKG}" \
    --apple-id "${APPLE_ID}" \
    --team-id "${APPLE_TEAM_ID}" \
    --password "${APPLE_APP_SPECIFIC_PASSWORD}" \
    --wait
  xcrun stapler staple "${FINAL_PKG}"
fi

# Also create standalone tar.gz archive for Homebrew / manual installs
ARCHIVE_STAGE="${STAGE_DIR}/archive"
mkdir -p "${ARCHIVE_STAGE}"
cp "${PAYLOAD_ROOT}/usr/local/bin/alt" "${ARCHIVE_STAGE}/alt"
cp "${REPO_ROOT}/LICENSE" "${REPO_ROOT}/README.md" "${ARCHIVE_STAGE}/"
cp -R "${PAYLOAD_ROOT}/usr/local/share" "${ARCHIVE_STAGE}/share"
tar -C "${ARCHIVE_STAGE}" -czf "${FINAL_TAR}" alt LICENSE README.md share

(
  cd "${OUT_DIR}"
  shasum -a 256 "${PKG_NAME}" "${TAR_NAME}" > SHA256SUMS
)

echo "==> Built artifacts in ${OUT_DIR}:"
echo "    - ${FINAL_PKG}"
echo "    - ${FINAL_TAR}"
echo "    - ${OUT_DIR}/SHA256SUMS"
