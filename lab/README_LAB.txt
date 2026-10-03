ACCESSLENS LAB: HOST-SAFE DEMONSTRATION
=======================================

This lab intentionally creates insecure settings on the local Linux system.
It is suitable only for a machine you control and can tolerate changing
temporarily. Do not run it on a production server.

The setup script requires root and the exact confirmation:
  yes-this-is-my-system

It creates only names prefixed with accesslens_lab, except for these dedicated
configuration files:
  /etc/sudoers.d/accesslens-lab
  /etc/cron.d/accesslens-lab
  /var/lib/accesslens/lab-manifest

Run from this directory:
  sudo ./setup_lab.sh
  sudo python3 -m accesslens.main scan --quick --format terminal,html,json
  sudo ./cleanup_lab.sh

Cleanup requires:
  yes-clean-accesslens-lab

The manifest is the cleanup authority. cleanup_lab.sh refuses to run without
it and validates its critical values before removing anything. Never manually
delete the manifest before cleanup.

The lab does NOT create a duplicate UID-0 account or an empty-password
account. Those cases remain safely covered by unit-test fixtures.
