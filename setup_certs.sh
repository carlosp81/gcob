#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="${CLN_CERT_DIR:-/etc/gcob/certs}"
USER_NAME="${GCOB_USER:-gcob}"
CLN_HOSTNAME="${CLN_HOSTNAME:-localhost}"

# Certificados fuente (generados por CLN)
CLN_CERT_DIR="${CLN_SOURCE_CERT_DIR:-/cln/certs}"

CERT_FILES=("ca.pem" "client.pem" "client-key.pem" "server.pem" "server-key.pem")

echo "=== Configuración de certificados para gcob ==="

# 1. Crear usuario si no existe
if ! id "$USER_NAME" &>/dev/null; then
    echo "[*] Creando usuario $USER_NAME..."
    useradd --system --shell /usr/sbin/nologin --no-create-home "$USER_NAME"
    echo "[*] Asignando contraseña para $USER_NAME..."
    passwd "$USER_NAME"
else
    echo "[✓] Usuario $USER_NAME ya existe."
fi

# 2. Crear directorio de certificados
echo "[*] Creando $CERT_DIR..."
mkdir -p "$CERT_DIR"

# 3. Copiar certificados
echo "[*] Copiando certificados desde $CLN_CERT_DIR..."
for cert in "${CERT_FILES[@]}"; do
    src="$CLN_CERT_DIR/$cert"
    dst="$CERT_DIR/$cert"
    if [ -f "$src" ]; then
        cp "$src" "$dst"
        echo "  [✓] Copiado $cert"
    else
        echo "  [!] No encontrado: $src"
        echo "      Buscando en $SCRIPT_DIR..."
        if [ -f "$SCRIPT_DIR/$cert" ]; then
            cp "$SCRIPT_DIR/$cert" "$dst"
            echo "  [✓] Copiado $cert desde $SCRIPT_DIR"
        else
            echo "  [!] $cert no encontrado en ninguna ubicación. Omitido."
        fi
    fi
done

# 4. Regenerar client.pem con Extended Key Usage=clientAuth
echo "[*] Regenerando client.pem con clientAuth..."
openssl req -new -key "$CERT_DIR/client-key.pem" \
  -out /tmp/client.csr \
  -subj "/CN=$CLN_HOSTNAME"
openssl x509 -req -in /tmp/client.csr \
  -CA "$CERT_DIR/ca.pem" \
  -CAkey "$CERT_DIR/ca-key.pem" \
  -CAcreateserial \
  -out "$CERT_DIR/client.pem" \
  -days 4096 \
  -extfile <(printf "extendedKeyUsage=clientAuth")
echo "  [✓] client.pem regenerado con clientAuth"

# 4b. Generar cert server para la API
echo "[*] Generando cert server para la API..."
openssl genrsa -out "$CERT_DIR/server-key.pem" 2048
openssl req -new -key "$CERT_DIR/server-key.pem" \
    -out /tmp/server.csr \
    -subj "/CN=$CLN_HOSTNAME" \
    -addext "subjectAltName=DNS:$CLN_HOSTNAME,DNS:localhost,IP:127.0.0.1"
openssl x509 -req -in /tmp/server.csr \
    -CA "$CERT_DIR/ca.pem" \
    -CAkey "$CERT_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$CERT_DIR/server.pem" \
    -days 365 \
    -extfile <(printf "subjectAltName=DNS:$CLN_HOSTNAME,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth")
echo "  [✓] server.pem generado y firmado con CA de CLN"
rm -f /tmp/server.csr

# 5. Aplicar permisos
echo "[*] Aplicando permisos..."

chown -R "${USER_NAME}:${USER_NAME}" "$CERT_DIR"
chmod 0700 "$CERT_DIR"
echo "  [✓] Directorio: 0700, propietario: $USER_NAME"

for cert in "${CERT_FILES[@]}"; do
    dst="$CERT_DIR/$cert"
    if [ -f "$dst" ]; then
        chown "${USER_NAME}:${USER_NAME}" "$dst"
        if [ "$cert" = "client-key.pem" ] || [ "$cert" = "server-key.pem" ]; then
            chmod 0400 "$dst"
            echo "  [✓] $cert → 0400 (clave privada)"
        elif [ "$cert" = "ca.pem" ] || [ "$cert" = "server.pem" ]; then
            chmod 0444 "$dst"
            echo "  [✓] $cert → 0444 (certificado)"
        else
            chmod 0400 "$dst"
            echo "  [✓] $cert → 0400 (identidad)"
        fi
    fi
done

# 5. Instalar binary si existe
if [ -f "$SCRIPT_DIR/target/release/gcob" ]; then
    echo "[*] Instalando binary a /usr/local/bin/gcob..."
    cp "$SCRIPT_DIR/target/release/gcob" /usr/local/bin/gcob
    chown root:root /usr/local/bin/gcob
    chmod 0755 /usr/local/bin/gcob
    echo "  [✓] Binary instalado"
fi

# 6. Configurar sudoers — permite gcob y grpcurl sin password
echo "[*] Configurando sudoers..."
SUDOERS_FILE="/etc/sudoers.d/gcob"
cat > "$SUDOERS_FILE" << SUDOEOF
user-admin ALL=($USER_NAME) NOPASSWD: /usr/local/bin/gcob, /usr/bin/grpcurl
SUDOEOF
chmod 0440 "$SUDOERS_FILE"
echo "  [✓] Sudoers configurado: gcob + grpcurl sin password"

# 7. Validar
echo ""
echo "=== Validación ==="
echo "[*] Verificando permisos del directorio..."
ls -ld "$CERT_DIR"
echo "[*] Verificando certificados..."
ls -la "$CERT_DIR"
echo ""
echo "[✓] Configuración completada."
echo ""
echo "Para iniciar la API:"
echo "  sudo -u $USER_NAME /usr/local/bin/gcob &"
echo ""
echo "Para probar con grpcurl:"
echo "  sudo -u $USER_NAME grpcurl -authority $CLN_HOSTNAME localhost:50003 cln.NodeServices/Getinfo | jq"
