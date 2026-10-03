"""Unit tests for SSH key discovery."""

import os

from accesslens.collectors.ssh_keys import collect_ssh_files
from accesslens.models import ScanContext


def test_ssh_collector_records_directory_and_key_files(tmp_path):
    root_home = tmp_path / "root"
    ssh = root_home / ".ssh"
    ssh.mkdir(parents=True)
    (ssh / "id_rsa").write_text("private")
    (ssh / "id_rsa.pub").write_text("public")
    (ssh / "authorized_keys").write_text("ssh-ed25519 key")
    context = ScanContext("host", "kernel", "time", "tester", False)
    collect_ssh_files(context, str(root_home), str(tmp_path / "homes"))
    paths = {record.path for record in context.ssh_files}
    assert str(ssh) in paths
    assert str(ssh / "id_rsa") in paths
    assert str(ssh / "authorized_keys") in paths
    assert str(ssh / "id_rsa.pub") not in paths
