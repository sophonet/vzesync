# Config file for storing secrets
import json
import argparse
from importlib.resources import files

import base64

# Logging to stdout and in-memory string buffer
import logging
import io

# Send report as e-mail
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate

import time

import os
from datetime import datetime
import re
from pathlib import Path
from glob import glob

# For communicating with platon host and pve host via SSH
import paramiko


class BlockingParamikoClient(object):
    keymap = {
        "ssh-rsa": paramiko.rsakey.RSAKey,
        "ssh-ed25519": paramiko.ed25519key.Ed25519Key
    }

    def __init__(
        self, hostname: str, hostkey: list, username: str, private_key: list
    ):
        self.client = paramiko.SSHClient()
        decoded_bytes = base64.b64decode(hostkey[1])
        hostkey_obj = paramiko.pkey.PKey.from_string(
            hostkey[0], decoded_bytes
        )
        self.client.get_host_keys().add(hostname, hostkey[0], hostkey_obj)
        private_key_io = io.StringIO(private_key[1])
        pkey = self.keymap[private_key[0]].from_private_key(
            file_obj=private_key_io
        )
        self.client.connect(hostname=hostname, username=username, pkey=pkey)

    def block_exec_command(self, command: str, quiet: bool) -> str:
        if not quiet:
            logging.info("Running remote command %s", command)
        _, stdout, stderr = self.client.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            error_message = stderr.read().decode("utf-8")
            logging.error("Exit status is %d: %s", exit_status, error_message)
        return stdout.read().decode("utf-8"), stderr.read().decode("utf-8")


class PVEAgent(BlockingParamikoClient):
    def __init__(
        self,
        hostname: str,
        hostkey: list,
        username: str,
        private_key: list,
        timestampfolder: str,
        pve_backup_drives: dict,
        scsi_drive: str,
        vmid: str
    ):
        super().__init__(hostname, hostkey, username, private_key)

        self.drive_id_folder: str = "/dev/disk/by-id"
        self.scsi_drive: str = scsi_drive
        self.vmid: str = vmid
        self.timestampfolder: str = timestampfolder
        self.pve_backup_drives: dict = pve_backup_drives

        self.backup_drive = None
        self.drive_path = None
        self.timestamp_path = None

    def backup_drive_present(self) -> bool:
        # Go through list of drive IDs and check if creation time is
        # newer than timestamp time
        stdout, _ = self.block_exec_command(
            f'ls -1 {self.drive_id_folder}', False
        )
        all_drives = stdout.split("\n")
        for backup_drive, backup_drive_id in self.pve_backup_drives.items():
            if backup_drive in all_drives:
                logging.info(
                    "Backup drive %s (%s) is plugged in",
                    backup_drive,
                    backup_drive_id
                )
                self.backup_drive = backup_drive
                self.drive_path = f"{self.drive_id_folder}/{backup_drive}"
                self.timestamp_path = f"{self.timestampfolder}/{backup_drive}"
                return True

        if self.backup_drive is None:
            logging.info("No backup drive connected")
            return False

    def backup_timestamp_outdated(self) -> bool:
        if not os.path.exists(self.timestamp_path):
            logging.info(
                "Backup timestamp for drive %s does not exist",
                self.backup_drive
            )
            return True

        time_stamp_stat = os.stat(self.timestamp_path)
        last_backup_time = datetime.fromtimestamp(time_stamp_stat.st_mtime)
        stdout, _ = self.block_exec_command(
            f'ls --full-time {self.drive_path}', False
        )
        date_time_pattern = re.search(
            r'[0-9]{4}-[0-9]{2}-[0-9]{2}\s[0-9]{2}:[0-9]{2}:[0-9]{2}', stdout
        )
        drive_insertion_time = datetime.strptime(
            date_time_pattern.group(0), '%Y-%m-%d %H:%M:%S'
        )
        if drive_insertion_time > last_backup_time:
            logging.info(
                "About to start backup since backup timestamp %s "
                "is older than drive insertion time stamp %s",
                last_backup_time.strftime('%Y-%m-%d %H:%M:%S'),
                drive_insertion_time.strftime('%Y-%m-%d %H:%M:%S')
            )
            return True

        logging.info(
            "Not starting another backup since backup timestamp %s "
            "is newer than drive insertion time stamp %s",
            last_backup_time.strftime('%Y-%m-%d %H:%M:%S'),
            drive_insertion_time.strftime('%Y-%m-%d %H:%M:%S')
        )
        return False

    def mount_drive_to_vm(self) -> None:
        # Configure VM for passing through backup disk
        logging.info("Add scsi device to VM")
        self.block_exec_command(
            f'qm set {self.vmid} -{self.scsi_drive} {self.drive_path}',
            False
        )
        time.sleep(2)

    def unmount_drive_from_vm(self) -> None:
        # Release backup disk passthrough from VM
        logging.info("Remove scsi device from VM")
        self.block_exec_command(
            f'qm set {self.vmid} --delete {self.scsi_drive}',
            False
        )
        time.sleep(2)
        if os.path.exists(self.timestamp_path):
            os.unlink(self.timestamp_path)
        Path(self.timestamp_path).touch()

    def close(self) -> None:
        self.client.close()


class ZFSAgent(BlockingParamikoClient):
    def __init__(
        self,
        hostname: str,
        hostkey: list,
        username: str,
        private_key: list,
        backuppool_name: str,
        backupfs_name: str,
        retention: dict,
        timestampfolder: str
    ):
        super().__init__(hostname, hostkey, username, private_key)
        self.backuppool_name = backuppool_name
        self.backupfs_name = backupfs_name
        self.retention = retention
        self.timestampfolder = timestampfolder
        self.block_exec_command(f"zpool import {self.backuppool_name}", False)
        self.block_exec_command(
            f"zfs load-key {self.backuppool_name}/{self.backupfs_name}",
            False
        )

    def backup_filesystems(self) -> list:
        stdout, _ = self.block_exec_command("zfs list", False)
        backup_filesystems = []
        for line in stdout.split("\n"):
            name_match = re.match(r"^[^\s]+", line)
            # name_match expression fails at last empty line
            if name_match is not None:
                name = name_match.group(0)
                # Only append non-backup files ystems that have a slash in
                # their name (i.e. are not root of the pool)
                if '/' in name and not name.startswith(self.backuppool_name):
                    logging.info("Found filesystem %s", line)
                    backup_filesystems.append(name)
        return backup_filesystems

    def zfssync(self, backup_filesystem: str) -> None:
        _, filesystemname = backup_filesystem.split('/')
        now = datetime.now()
        timestamp = now.strftime("%Y-%m-%d_%H:%M:%S")

        latest_snapshot_in_backuppool = None

        # Determine sorted list of snapshots on backuppool
        stdout, stderr = self.block_exec_command(
            f"zfs list -t snapshot {self.backuppool_name}/"
            f"{self.backupfs_name}/{filesystemname}",
            False
        )
        backup_snapshots = []
        logging.info("Existing backups:")
        logging.info(stdout)
        for line in stdout.split("\n"):
            date_time_pattern = re.search(
                r'[0-9]{4}-[0-9]{2}-[0-9]{2}_'
                r'[0-9]{2}:[0-9]{2}:[0-9]{2}',
                line
            )
            if date_time_pattern is not None:
                backup_snapshots.append(
                    datetime.strptime(
                        date_time_pattern.group(0), '%Y-%m-%d_%H:%M:%S'
                    )
                )
        backup_snapshots = sorted(backup_snapshots)

        # Determine latest snapshot in backuppool
        stdout, stderr = self.block_exec_command(
            f"zfs list -t snapshot {backup_filesystem}",
            False
        )
        logging.info("Existing snapshots:")
        logging.info(stdout)
        for line in stdout.split("\n"):
            date_time_pattern = re.search(
                r'[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}:[0-9]{2}:[0-9]{2}',
                line
            )
            if date_time_pattern is not None:
                logging.info(
                    "Check if snapshot %s is present on backup...",
                    date_time_pattern.group(0)
                )
                existing_timestamp = datetime.strptime(
                    date_time_pattern.group(0), '%Y-%m-%d_%H:%M:%S'
                )
                if (
                    existing_timestamp in backup_snapshots and
                    (latest_snapshot_in_backuppool is None or
                     existing_timestamp > latest_snapshot_in_backuppool)
                ):
                    latest_snapshot_in_backuppool = existing_timestamp
                    logging.info(
                        "...found and newer than potentially existing ones"
                    )
                else:
                    logging.info("...not available")

        logging.info(
            "Creating snapshot %s on filesystem %s",
            timestamp, backup_filesystem
        )
        self.block_exec_command(
            f"zfs snapshot {backup_filesystem}@{timestamp}",
            False
        )

        if latest_snapshot_in_backuppool is not None:
            existing_snapshot_string = latest_snapshot_in_backuppool.strftime(
                "%Y-%m-%d_%H:%M:%S"
            )
            # Determine latest snapshot present on backuppool
            logging.info(
                "Syncing filesystem %s based on snapshot %s",
                backup_filesystem,
                latest_snapshot_in_backuppool
            )
            stdout, stderr = self.block_exec_command(
                f"zfs send -i {backup_filesystem}@{existing_snapshot_string} "
                f"{backup_filesystem}@{timestamp} | "
                f"zfs recv {self.backuppool_name}/"
                f"{self.backupfs_name}/"
                f"{filesystemname}",
                False
            )
            logging.info("Output of sync command: %s", stderr)
            # Delete snapshot on data pool that has been used for backup
            logging.info(
                "Destroying snapshot %s",
                {backup_filesystem}@{existing_snapshot_string}
            )
            self.block_exec_command(
                f"zfs destroy {backup_filesystem}@{existing_snapshot_string}",
                False
            )
        else:
            # If not present, backup snapshot completely
            logging.info("Syncing filesystem %s completely", backup_filesystem)

            # There are backups with non-matching snapshots,
            # need to delete snapshots first
            for backup_snapshot in backup_snapshots:
                timestamp_to_destroy_string = backup_snapshot.strftime(
                    "%Y-%m-%d_%H:%M:%S"
                )
                logging.info(
                    "Destroying old non-matching backup with timestamp %s",
                    timestamp_to_destroy_string
                )
                self.block_exec_command(
                    f"zfs destroy {self.backuppool_name}/"
                    f"{self.backupfs_name}/{filesystemname}@"
                    f"{timestamp_to_destroy_string}",
                    False
                )

            # Remove filesystem itself
            stdout, stderr = self.block_exec_command(
                f"zfs list -r {self.backuppool_name}",
                False
            )
            for line in stdout.split("\n"):
                if line.startswith(
                    f"{self.backuppool_name}/"
                    f"{self.backupfs_name}/"
                    f"{filesystemname}"
                ):
                    # Add '-r' flag to recursively destroy snapshots
                    # that do not follow timestamp pattern
                    self.block_exec_command(
                        f"zfs destroy -r {self.backuppool_name}/"
                        f"{self.backupfs_name}/{filesystemname}",
                        False
                    )

            stdout, stderr = self.block_exec_command(
                f"zfs send {backup_filesystem}@{timestamp} | "
                f"zfs recv {self.backuppool_name}/"
                f"{self.backupfs_name}/{filesystemname}",
                False
            )
            logging.info("Output of sync command: %s", stderr)

        backups_to_keep = self.retention["default"]
        if filesystemname in self.retention:
            backups_to_keep = self.retention[filesystemname]

        # Remove number of backups to keep by one, since
        # list of backup_snapshots has been generated before generating
        # a new snapshot in this function
        backups_to_keep -= 1

        if len(backup_snapshots) > backups_to_keep:
            for timestamp_to_destroy in backup_snapshots[:-backups_to_keep]:
                timestamp_to_destroy_string = timestamp_to_destroy.strftime(
                    "%Y-%m-%d_%H:%M:%S"
                )
                logging.info(
                    "Destroying old backup with timestamp %s",
                    timestamp_to_destroy_string
                )
                self.block_exec_command(
                    f"zfs destroy {self.backuppool_name}/"
                    f"{self.backupfs_name}/{filesystemname}@"
                    f"{timestamp_to_destroy_string}",
                    False
                )

    def remove_obsolete_snapshots(self) -> None:
        # Determine oldest date from all timestamps
        oldest_timestamp = datetime.now()
        for timestamp_path in glob(self.timestampfolder + "/*"):
            time_stamp_stat = os.stat(timestamp_path)
            last_backup_time = datetime.fromtimestamp(time_stamp_stat.st_mtime)
            if last_backup_time < oldest_timestamp:
                oldest_timestamp = last_backup_time

        for filesystem in self.backup_filesystems():
            # Determine list of snapshots on filesystem
            stdout, _ = self.block_exec_command(
                f"zfs list -t snapshot {filesystem}",
                False
            )
            for line in stdout.split("\n"):
                date_time_pattern = re.search(
                    r'[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}:[0-9]{2}:[0-9]{2}',
                    line
                )
                if date_time_pattern is not None:
                    logging.info(
                        "Check if snapshot %s is present on backup...",
                        date_time_pattern.group(0)
                    )
                    existing_timestamp = datetime.strptime(
                        date_time_pattern.group(0), '%Y-%m-%d_%H:%M:%S'
                    )
                    if existing_timestamp < oldest_timestamp:
                        logging.info(
                            "...found and older than %s",
                            oldest_timestamp.strftime('%Y-%m-%d %H:%M:%S')
                        )
                        # Delete obsolete snapshot, not required anymore
                        # for incremental backups
                        logging.info(
                            "Destroying snapshot %s",
                            existing_timestamp.strftime('%Y-%m-%d_%H:%M:%S')
                        )
                        snapshot_name = existing_timestamp.strftime(
                            '%Y-%m-%d_%H:%M:%S'
                        )
                        self.block_exec_command(
                            f"zfs destroy {filesystem}@{snapshot_name}",
                            False
                        )

    def close(self) -> None:
        self.block_exec_command(f"zpool scrub {self.backuppool_name}", False)
        time.sleep(2)
        running = True
        while running:
            time.sleep(60)
            stdout, _ = self.block_exec_command(
                f"zpool status {self.backuppool_name}", True
            )
            running = (
                re.search(
                    "scan: scrub in progress since",
                    stdout,
                    re.MULTILINE
                )
                is not None
            )

        stdout, _ = self.block_exec_command("zpool list", False)
        logging.info(stdout)
        stdout, _ = self.block_exec_command(
            f"zfs get compressratio "
            f"{self.backuppool_name}/{self.backupfs_name}",
            False
        )
        logging.info(stdout)
        logging.info("Exporting %s", self.backuppool_name)
        self.block_exec_command(f"zpool export {self.backuppool_name}", False)
        time.sleep(2)
        self.client.close()


def send_log_via_mail(
    attachments: dict,
    send_from: str,
    send_to: list,
    subject: str,
    body: str,
    smtp_host: str,
    smtp_username: str,
    smtp_password: str
):
    assert isinstance(send_to, list)

    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject

    msg.attach(MIMEText(body))

    for name, attachment in attachments.items():
        part = MIMEApplication(
            attachment,
            Name=name
        )
        part['Content-Disposition'] = f'attachment; filename={name}'
        msg.attach(part)

    try:
        conn = smtplib.SMTP_SSL(smtp_host)
        conn.login(smtp_username, smtp_password)
        conn.sendmail(send_from, send_to, msg.as_string())
        conn.close()

    except smtplib.SMTPResponseException as e:
        error_message = e.smtp_error
        logging.error("SMTP Error: %s", error_message)


def main_loop(config):
    while True:
        pve_agent_ = PVEAgent(**config["pvehost"])
        if pve_agent_.backup_drive_present() and \
                pve_agent_.backup_timestamp_outdated():
            logbuffer = io.StringIO()
            bufferhandler = logging.StreamHandler(logbuffer)
            logging.getLogger().addHandler(bufferhandler)
            pve_agent_.mount_drive_to_vm()
            zfs_agent_ = ZFSAgent(**config["zfshost"])
            for backup_folder in zfs_agent_.backup_filesystems():
                zfs_agent_.zfssync(backup_folder)
            zfs_agent_.remove_obsolete_snapshots()
            zfs_agent_.close()
            pve_agent_.unmount_drive_from_vm()
            logging.getLogger().removeHandler(bufferhandler)
            send_log_via_mail(
                attachments={"backup.log": logbuffer.getvalue()},
                **config["email"]
            )
        pve_agent_.close()
        logging.info("Finished backup process, waiting 1 hour")
        time.sleep(3600)


def load_example_config():
    config_path = files('vzesync').joinpath('../examples/config.json')
    return json.loads(config_path.read_text())


def main():
    parser = argparse.ArgumentParser(
        description="VZE Sync - Backup tool for VM utilizing encrypted ZFS"
    )
    parser.add_argument("--config", help="Path to config file")
    parser.add_argument(
        "--print-example",
        action="store_true",
        help="Print example config"
    )
    args = parser.parse_args()

    if args.print_example:
        print(json.dumps(load_example_config(), indent=2))
        return

    if args.config:
        config_path = args.config
    else:
        config_path = '/etc/vzesync/config.json'

    logging.basicConfig(level=logging.INFO)
    logging.info("Starting vzesync")
    with open(config_path, encoding='utf-8') as config_file:
        config = json.load(config_file)

    # Create timestamp folder if it does not exist
    os.makedirs(config["pvehost"]["timestampfolder"], exist_ok=True)

    main_loop(config)
