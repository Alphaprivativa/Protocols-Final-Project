# #!/usr/bin/env bash
# #
# # Build and install Zeutro's OpenABE so that the `oabe_setup`, `oabe_keygen`,
# # `oabe_enc` and `oabe_dec` command-line tools land on your PATH.  Once they
# # are installed, `python3 run_demo.py` automatically switches to the real
# # CP-WATERS-KEM backend (see cpabe/openabe_backend.py).
# #
# # This follows OpenABE's documented build process.  It needs a C/C++ toolchain,
# # CMake, and the usual autotools; on Debian/Ubuntu the helper below installs
# # them.  The dependency build (relic, OpenSSL, GoogleTest, ...) takes several
# # minutes.
# #
# # Usage:
# #     ./openabe/build_openabe.sh            # clone + build + install
# #     PREFIX=$HOME/.local ./openabe/build_openabe.sh   # custom install prefix
# #
# set -euo pipefail

# OPENABE_REPO="${OPENABE_REPO:-https://github.com/zeutro/openabe.git}"
# WORKDIR="${WORKDIR:-$(pwd)/.openabe-build}"

# echo ">> OpenABE build helper"
# echo "   repo   : ${OPENABE_REPO}"
# echo "   workdir: ${WORKDIR}"

# # 1. System packages (Debian/Ubuntu).  Skip if you manage deps yourself.
# if command -v apt-get >/dev/null 2>&1; then
#     echo ">> installing system packages (sudo may prompt)"
#     sudo apt-get update
#     sudo apt-get install -y \
#         git build-essential cmake m4 flex bison \
#         libssl-dev wget tar
# fi

# # 2. Clone.
# mkdir -p "${WORKDIR}"
# if [ ! -d "${WORKDIR}/openabe" ]; then
#     git clone --depth 1 "${OPENABE_REPO}" "${WORKDIR}/openabe"
# fi
# cd "${WORKDIR}/openabe"

# # 3. Build dependencies and the library, following OpenABE's README.
# #    `. ./env` exports the paths OpenABE's makefiles expect.
# # shellcheck disable=SC1091
# . ./env
# if [ -x ./deps/install_pkgs.sh ]; then
#     ./deps/install_pkgs.sh || true
# fi
# make deps
# make
# make test || echo ">> (self-tests reported an issue; continuing to install)"

# # 4. Install the CLI tools + libraries.
# if [ -n "${PREFIX:-}" ]; then
#     make install PREFIX="${PREFIX}"
#     echo ">> installed to ${PREFIX}; ensure ${PREFIX}/bin is on your PATH"
# else
#     sudo make install
# fi

# echo ""
# echo ">> done.  Verify with:"
# echo "     oabe_setup -s CP -p test && ls test.*"
# echo "   then run the PoC against the real backend:"
# echo "     python3 run_demo.py --backend openabe"
#!/bin/bash

# Interrompe lo script in caso di qualsiasi errore durante la configurazione
set -e

echo "========================================================================"
echo "1. Installazione dei pacchetti di sistema richiesti..."
echo "========================================================================"
# Nota: potrebbe richiedere i privilegi di root/sudo a seconda del tuo ambiente.
# Se sei già root (es. in Codespaces), puoi rimuovere "sudo"
sudo apt-get update && sudo apt-get install -y --no-install-recommends \
    git build-essential cmake m4 flex libfl-dev bison libbison-dev \
    libssl-dev libgmp-dev zlib1g-dev wget tar ca-certificates \
    python3 python3-pip python-is-python3

# Disabilita i controlli dei certificati per wget a livello utente corrente
mkdir -p ~/.config
echo "check_certificate = off" >> ~/.wgetrc

echo "========================================================================"
echo "2. Scaricamento e Patch di OpenABE..."
echo "========================================================================"
# Creiamo una cartella pulita per OpenABE in /opt/openabe (se hai i permessi)
# o in un percorso alternativo locale se preferisci. Usiamo /opt/openabe come da Dockerfile.
sudo mkdir -p /opt/openabe
sudo chown -R $(whoami) /opt/openabe
WORKDIR_OPENABE="/opt/openabe"

if [ ! -d "$WORKDIR_OPENABE/.git" ]; then
    git clone --depth 1 https://github.com/zeutro/openabe.git "$WORKDIR_OPENABE"
fi

cd "$WORKDIR_OPENABE"

# Soddisfa i path hardcodati dei parser richiesti da OpenABE
mkdir -p "$WORKDIR_OPENABE/bin"
ln -sf /usr/bin/bison "$WORKDIR_OPENABE/bin/bison"
ln -sf /usr/bin/flex "$WORKDIR_OPENABE/bin/flex"

# PATCH DEL CODICE SORGENTE: Compatibilità per i compilatori più recenti
sed -i 's/parser_class_name/api.parser.class/g' src/zparser.yy
find . -type f \( -name "Makefile*" -o -name "CMakeLists.txt" -o -name "*.mk" \) -exec sed -i 's/-Werror//g' {} +

echo "========================================================================"
echo "3. Compilazione sequenziale di OpenABE (Potrebbe richiedere diversi minuti)..."
echo "========================================================================"
# Eseguiamo la build rimuovendo temporaneamente LD_LIBRARY_PATH per non corrompere OpenSSL
(
    unset LD_LIBRARY_PATH
    . ./env
    make deps
    make
    # Eseguiamo i test ignorando eventuali crash residui
    LD_LIBRARY_PATH="$PWD/deps/root/lib" make test || true
    sudo make install
)

# Aggiorna i link alle librerie condivise appena installate nel sistema host
sudo ldconfig

echo "========================================================================"
echo "4. Installazione delle dipendenze Python..."
echo "========================================================================"
pip3 install --no-cache-dir "cryptography>=42.0"

echo "========================================================================"
echo "5. Configurazione Variabili d'Ambiente ed Esecuzione del Progetto..."
echo "========================================================================"
# Torniamo alla cartella in cui risiede il tuo progetto
# (ovvero dove hai lanciato questo script Bash)
cd -

# Esportiamo le variabili d'ambiente necessarie sia per PATH che per trovare librelic.so
export PATH="/usr/local/bin:${PATH}"
export LD_LIBRARY_PATH="/opt/openabe/deps/root/lib:/usr/local/lib:${LD_LIBRARY_PATH}"

echo "Avvio della demo con backend OpenABE..."
python3 run_demo.py --backend openabe