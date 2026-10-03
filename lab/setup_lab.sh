#!/usr/bin/env bash
# AccessLens demonstration lab setup.
#
# This script deliberately creates insecure, clearly prefixed demo objects on
# the local Linux host. It never runs automatically and requires an explicit
# confirmation because the lab changes real system state.
set -euo pipefail

LAB_USER="accesslens_labuser"
LAB_ROOT="/opt/accesslens_lab"
SUDOERS_FILE="/etc/sudoers.d/accesslens-lab"
CRON_FILE="/etc/cron.d/accesslens-lab"
MANIFEST_DIR="/var/lib/accesslens"
MANIFEST="${MANIFEST_DIR}/lab-manifest"
CONFIRMATION="yes-this-is-my-system"

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: run this script as root (sudo is required)." >&2
    exit 1
fi

cat <<'WARNING'
WARNING: this modifies the LOCAL SYSTEM for a security demonstration.
It creates a test user, a passwordless sudo rule, weak permissions, a SUID
copy of find, a loose SSH key, and a root cron job. Run only when you accept
these changes and will run cleanup_lab.sh afterward.
WARNING
read -r -p "Type yes-this-is-my-system to continue: " confirmation
if [[ "${confirmation}" != "${CONFIRMATION}" ]]; then
    echo "Cancelled; no lab objects were created."
    exit 1
fi

if [[ -e "${MANIFEST}" ]]; then
    echo "ERROR: an existing lab manifest was found: ${MANIFEST}" >&2
    echo "Run cleanup_lab.sh first, or inspect it manually." >&2
    exit 1
fi
if id "${LAB_USER}" >/dev/null 2>&1; then
    echo "ERROR: ${LAB_USER} already exists; refusing to modify it." >&2
    exit 1
fi

mkdir -p "${MANIFEST_DIR}"
printf 'LAB_USER=%s\nLAB_ROOT=%s\nSUDOERS_FILE=%s\nCRON_FILE=%s\n' \
    "${LAB_USER}" "${LAB_ROOT}" "${SUDOERS_FILE}" "${CRON_FILE}" > "${MANIFEST}"
printf 'MANIFEST=%s\n' "${MANIFEST}" >> "${MANIFEST}"

# useradd = "add user"; -M avoids creating a home automatically because this
# demonstration creates its exact home directory below.
useradd --no-create-home --shell /usr/sbin/nologin "${LAB_USER}"
printf 'USER_CREATED=1\n' >> "${MANIFEST}"

# mkdir = "make directory"; -p creates missing parents without failing when
# an explicitly managed parent already exists.
mkdir -p "${LAB_ROOT}"
printf 'LAB_ROOT_CREATED=1\n' >> "${MANIFEST}"
mkdir -p "/home/${LAB_USER}/.ssh"
chown -R "${LAB_USER}:${LAB_USER}" "/home/${LAB_USER}"
printf 'HOME_CREATED=1\n' >> "${MANIFEST}"

# printf writes a sudoers candidate; visudo = "validate sudoers" checks syntax
# before install copies it into the live include directory.
candidate="$(mktemp)"
printf '%s ALL=(ALL:ALL) NOPASSWD: ALL\n' "${LAB_USER}" > "${candidate}"
chmod 0440 "${candidate}"
visudo -cf "${candidate}"
install -o root -g root -m 0440 "${candidate}" "${SUDOERS_FILE}"
rm -f "${candidate}"
printf 'SUDOERS_CREATED=1\n' >> "${MANIFEST}"

touch "${LAB_ROOT}/world_writable.conf"
chmod 0777 "${LAB_ROOT}/world_writable.conf"
printf 'WORLD_WRITABLE_FILE=%s\n' "${LAB_ROOT}/world_writable.conf" >> "${MANIFEST}"

mkdir -p "${LAB_ROOT}/open_dir"
chmod 0777 "${LAB_ROOT}/open_dir"
printf 'WORLD_WRITABLE_DIR=%s\n' "${LAB_ROOT}/open_dir" >> "${MANIFEST}"

# cp = "copy"; this creates a harmless copy, not a modified system binary.
cp /usr/bin/find "${LAB_ROOT}/find_suid"
chmod 4755 "${LAB_ROOT}/find_suid"
printf 'SUID_FILE=%s\n' "${LAB_ROOT}/find_suid" >> "${MANIFEST}"

printf 'demo-private-key\n' > "/home/${LAB_USER}/.ssh/id_rsa"
chmod 0644 "/home/${LAB_USER}/.ssh/id_rsa"
chown "${LAB_USER}:${LAB_USER}" "/home/${LAB_USER}/.ssh/id_rsa"
printf 'SSH_KEY=%s\n' "/home/${LAB_USER}/.ssh/id_rsa" >> "${MANIFEST}"

printf 'SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n* * * * * root %s/backup.sh\n' "${LAB_ROOT}" > "${LAB_ROOT}/cron-entry"
printf '#!/bin/sh\necho accesslens lab\n' > "${LAB_ROOT}/backup.sh"
chmod 0666 "${LAB_ROOT}/backup.sh"
chown root:root "${LAB_ROOT}/backup.sh"
install -o root -g root -m 0644 "${LAB_ROOT}/cron-entry" "${CRON_FILE}"
printf 'CRON_SCRIPT=%s\nCRON_CREATED=1\n' "${LAB_ROOT}/backup.sh" >> "${MANIFEST}"
rm -f "${LAB_ROOT}/cron-entry"

echo "Lab setup complete. Manifest: ${MANIFEST}"
echo "Run: sudo python3 -m accesslens.main scan --quick"
echo "After the demonstration, run: sudo ./cleanup_lab.sh"
