#!/usr/bin/env bash
# AccessLens demonstration lab cleanup.
#
# Cleanup is manifest-driven and removes only the exact objects created by
# setup_lab.sh. It refuses to guess paths when the manifest is absent.
set -euo pipefail

MANIFEST="/var/lib/accesslens/lab-manifest"
CONFIRMATION="yes-clean-accesslens-lab"

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: run this script as root (sudo is required)." >&2
    exit 1
fi
if [[ ! -f "${MANIFEST}" ]]; then
    echo "ERROR: no lab manifest found at ${MANIFEST}; refusing broad cleanup." >&2
    exit 1
fi

echo "This removes only objects recorded by ${MANIFEST}."
read -r -p "Type yes-clean-accesslens-lab to continue: " confirmation
if [[ "${confirmation}" != "${CONFIRMATION}" ]]; then
    echo "Cancelled; no lab objects were removed."
    exit 1
fi

# Read exact values from the script-owned manifest. No manifest line is
# executed as shell code.
LAB_USER=""
LAB_ROOT=""
SUDOERS_FILE=""
CRON_FILE=""
CRON_SCRIPT=""
SSH_KEY=""
while IFS='=' read -r key value; do
    case "${key}" in
        LAB_USER) LAB_USER="${value}" ;;
        LAB_ROOT) LAB_ROOT="${value}" ;;
        SUDOERS_FILE) SUDOERS_FILE="${value}" ;;
        CRON_FILE) CRON_FILE="${value}" ;;
        CRON_SCRIPT) CRON_SCRIPT="${value}" ;;
        SSH_KEY) SSH_KEY="${value}" ;;
    esac
done < "${MANIFEST}"

[[ "${LAB_USER}" == "accesslens_labuser" ]]
[[ "${LAB_ROOT}" == "/opt/accesslens_lab" ]]
[[ "${SUDOERS_FILE}" == "/etc/sudoers.d/accesslens-lab" ]]
[[ "${CRON_FILE}" == "/etc/cron.d/accesslens-lab" ]]
[[ "${CRON_SCRIPT}" == "${LAB_ROOT}/backup.sh" ]]
[[ "${SSH_KEY}" == "/home/${LAB_USER}/.ssh/id_rsa" ]]

# rm = "remove"; these are exact manifest paths, never a wildcard.
rm -f "${SUDOERS_FILE}" "${CRON_FILE}" "${CRON_SCRIPT}" "${SSH_KEY}"
rm -f "${LAB_ROOT}/world_writable.conf" "${LAB_ROOT}/find_suid"
rm -rf "${LAB_ROOT}/open_dir"
rm -rf "/home/${LAB_USER}"
if id "${LAB_USER}" >/dev/null 2>&1; then
    # userdel = "delete user"; -r removes the account's managed home if any.
    userdel -r "${LAB_USER}"
fi
rm -rf "${LAB_ROOT}"
rm -f "${MANIFEST}"
rmdir --ignore-fail-on-non-empty "$(dirname "${MANIFEST}")" 2>/dev/null || true

echo "AccessLens lab cleanup complete."
