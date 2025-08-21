VERSION="v0.1.0"
REPO_URL="https://codeload.github.com/KianiDev/phantomd/tar.gz/refs/tags/$VERSION"
INSTALL_DIR="/opt/phantomd"
VENV_DIR="$INSTALL_DIR/venv"
SERVICE_NAME="phantomd"

echo "phantomd installer (version $VERSION, headless)"

# ensure running as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This installer must be run as root."
  exit 1
fi

mkdir -p "$INSTALL_DIR"
chown root:root "$INSTALL_DIR"

TMP_TAR="/tmp/phantomd.tar.gz"
echo "Fetching repository tarball..."
curl -fsSL "$REPO_URL" -o "$TMP_TAR"

echo "Extracting..."
tar xzf "$TMP_TAR" -C /tmp
EXTRACTED_DIR="/tmp/phantomd-$VERSION"

if [ ! -d "$EXTRACTED_DIR" ]; then
  echo "Unexpected archive layout. Please inspect /tmp"
  exit 1
fi

cp -a "$EXTRACTED_DIR"/* "$INSTALL_DIR/"
rm -f "$TMP_TAR"
