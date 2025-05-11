''' VZE Sync - Backup tool for VM utilizing encrypted ZFS
'''
# Config file for storing secrets
import json
import argparse
from importlib.resources import files
from typing import Optional

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


# pylint: disable-next=too-few-public-methods
class BlockingParamikoClient:
    ''' Base class for SSH connections using paramiko. It provides
        a convenience function block_exec_command() that executes
        a comman remotely and wait until error and output are available.
    '''
    keymap = {
        "ssh-rsa": paramiko.rsakey.RSAKey,
        "ssh-ed25519": paramiko.ed25519key.Ed25519Key
    }

    def __init__(
        self, hostname: str, hostkey: list, username: str, private_key: list
    ):
        self.client = paramiko.SSHClient()
        decoded_bytes = base64.b64decode(hostkey[1])
        hostkey_obj = paramiko.PKey.from_type_string(
            hostkey[0], decoded_bytes
        )
        self.client.get_host_keys().add(hostname, hostkey[0], hostkey_obj)
        private_key_io = io.StringIO(private_key[1])
        pkey = self.keymap[private_key[0]].from_private_key(
            file_obj=private_key_io
        )
        self.client.connect(hostname=hostname, username=username, pkey=pkey)

    def block_exec_command(self, command: str, quiet: bool) -> str:
        ''' Execute command remotely and wait until finished '''
        if not quiet:
            logging.info("Running remote command %s", command)
        _, stdout, stderr = self.client.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            error_message = stderr.read().decode("utf-8")
            logging.error("Exit status is %d: %s", exit_status, error_message)
        return stdout.read().decode("utf-8"), stderr.read().decode("utf-8")


# pylint: disable-next=too-many-instance-attributes
class PVEAgent(BlockingParamikoClient):
    ''' Class for communicating with Proxmox VE host via SSH.
        This is done for periodically checking the presence of
        backup drives, mounting them to the VM and unmounting them
        after the backup is done.
    '''
    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
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
        ''' Checks if a backup drive is present as a device '''
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

        logging.info("No backup drive connected")
        return False

    def backup_timestamp_outdated(self) -> bool:
        ''' Checks if the backup timestamp of the drive is older
            than the drive insertion time.
        '''
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
        ''' Mounts the backup drive to the VM by using qm set. '''
        logging.info("Add scsi device to VM")
        self.block_exec_command(
            f'qm set {self.vmid} -{self.scsi_drive} {self.drive_path}',
            False
        )
        time.sleep(2)

    def unmount_drive_from_vm(self) -> None:
        ''' Unmounts the backup drive from the VM by using qm set --delete and
            updates the backup timestamp
        '''
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
        ''' Disconnect the SSH session '''
        self.client.close()


class ZFSAgent(BlockingParamikoClient):
    ''' Class for communicating with ZFS host via SSH once it has been mounted.
    '''
    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
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
        self.date_time_pattern = re.compile(
            r'[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}:[0-9]{2}:[0-9]{2}'
        )

    def snapshot_timestamps(self, zfs_filesystem: str) -> list[datetime]:
        ''' Retrieve a sorted list of timestamps of a zfs filesystem '''
        # Determine sorted list of snapshots on backuppool
        stdout, _ = self.block_exec_command(
            f"zfs list -t snapshot {zfs_filesystem}",
            False
        )
        snapshots = stdout.split("\n")
        timestamp_matches = [
            self.date_time_pattern.search(snapshot) for snapshot in snapshots
        ]
        timestamps = [
            datetime.strptime(
                match.group(0), '%Y-%m-%d_%H:%M:%S'
            )
            for match in timestamp_matches if match is not None
        ]
        return sorted(timestamps)

    def zfs_filesystems(self) -> list[str]:
        ''' Retrieve a list of zfs filesystems that are not
            part of the backup pool
        '''
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

    def incremental_backup(
        self,
        zfs_filesystem: str,
        base_snapshot: str,
        timestamp: str
    ) -> None:
        ''' Performs a zfs incremental sync based on the base snapshot '''
        fs_name = zfs_filesystem.split('/')[-1]

        # Determine latest snapshot present on backuppool
        logging.info(
            "Syncing filesystem %s based on snapshot %s",
            zfs_filesystem,
            base_snapshot
        )
        _, stderr = self.block_exec_command(
            f"zfs send -i {zfs_filesystem}@{base_snapshot} "
            f"{zfs_filesystem}@{timestamp} | "
            f"zfs recv {self.backuppool_name}/"
            f"{self.backupfs_name}/"
            f"{fs_name}",
            False
        )
        logging.info("Errors of sync command: %s", stderr)

    def full_backup(self, zfs_filesystem, timestamp: str) -> None:
        ''' Performs a full zfs sync without a base snapshot '''
        fs_name = zfs_filesystem.split('/')[-1]

        # If not present, backup snapshot completely
        logging.info("Syncing filesystem %s completely", zfs_filesystem)

        _, stderr = self.block_exec_command(
            f"zfs send {zfs_filesystem}@{timestamp} | "
            f"zfs recv {self.backuppool_name}/"
            f"{self.backupfs_name}/{fs_name}",
            False
        )
        logging.info("Error of sync command: %s", stderr)

    def remove_filesystem_if_exists(self, zfs_filesystem: str) -> None:
        ''' Removes a filesystem if it exists '''
        pool_name = zfs_filesystem.split('/')[0]
        # Remove filesystem itself
        stdout, _ = self.block_exec_command(
            f"zfs list -r {pool_name}",
            False
        )
        filesystems = stdout.split("\n")
        for filesystem in filesystems:
            if filesystem.startswith(zfs_filesystem):
                # Add '-r' flag to recursively destroy snapshots
                # that do not follow timestamp pattern
                self.block_exec_command(
                    f"zfs destroy -r {zfs_filesystem}",
                    False
                )
                return

    def remove_obsolete_backup_snapshots(
        self, filesystemname: str, backup_snapshots: list
    ) -> None:
        ''' Remove obsolete backup snapshots according to
            the retention policy (number of copies to keep)
        '''
        backups_to_keep = self.retention["default"]
        if filesystemname in self.retention:
            backups_to_keep = self.retention[filesystemname]

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

    def newest_snapshot_in_given_list(
        self, zfs_filesystem: str, given_timestamps: list[datetime]
    ) -> Optional[datetime]:
        ''' Retrieves the newest snapshot of zfs_filesystem
            that is present in a given list
        '''
        timestamps = self.snapshot_timestamps(zfs_filesystem)

        valid_timestamps = [
            timestamp for timestamp in timestamps
            if timestamp in given_timestamps
        ]

        if len(valid_timestamps) == 0:
            return None

        return valid_timestamps[-1]

    def zfssync(self, zfs_filesystem: str) -> None:
        ''' Syncs a filesystem to the backup pool. '''
        fs_name = zfs_filesystem.split('/')[1]
        now_stamp = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")

        logging.info(
            "Creating snapshot %s on filesystem %s",
            now_stamp, zfs_filesystem
        )
        self.block_exec_command(
            f"zfs snapshot {zfs_filesystem}@{now_stamp}",
            False
        )

        backup_timestamps = self.snapshot_timestamps(
            f"{self.backuppool_name}/{self.backupfs_name}/{fs_name}"
        )

        newest_snapshot = self.newest_snapshot_in_given_list(
            zfs_filesystem, backup_timestamps
        )

        if newest_snapshot is not None:
            self.incremental_backup(
                zfs_filesystem,
                newest_snapshot.strftime("%Y-%m-%d_%H:%M:%S"),
                now_stamp
            )
        else:
            self.remove_filesystem_if_exists(
                f"{self.backuppool_name}/{self.backupfs_name}/{fs_name}"
            )
            self.full_backup(zfs_filesystem, now_stamp)

        self.remove_obsolete_backup_snapshots(fs_name, backup_timestamps)

    def remove_obsolete_snapshots(self) -> None:
        ''' Remove obsolete snapshots of filesystems that are older
            than the oldest backup drive timestamp
        '''
        # Determine oldest date from all timestamps
        oldest_timestamp = datetime.now()

        for timestamp_path in glob(self.timestampfolder + "/*"):
            time_stamp_stat = os.stat(timestamp_path)
            last_backup_time = datetime.fromtimestamp(time_stamp_stat.st_mtime)
            if last_backup_time < oldest_timestamp:
                oldest_timestamp = last_backup_time

        for zfs_filesystem in self.zfs_filesystems():
            # Determine list of snapshots on filesystem
            stdout, _ = self.block_exec_command(
                f"zfs list -t snapshot {zfs_filesystem}",
                False
            )
            snapshots = stdout.split("\n")

            timestamp_matches = [
                self.date_time_pattern.search(snapshot)
                for snapshot in snapshots
            ]

            timestamps = [
                datetime.strptime(
                    match.group(0), '%Y-%m-%d_%H:%M:%S'
                )
                for match in timestamp_matches if match is not None
            ]

            for timestamp in timestamps:
                if timestamp < oldest_timestamp:
                    logging.info(
                        "...found and older than %s",
                        oldest_timestamp.strftime('%Y-%m-%d %H:%M:%S')
                    )
                    # Delete obsolete snapshot, not required anymore
                    # for incremental backups
                    logging.info(
                        "Destroying snapshot %s",
                        timestamp.strftime('%Y-%m-%d_%H:%M:%S')
                    )
                    snapshot_name = timestamp.strftime(
                        '%Y-%m-%d_%H:%M:%S'
                    )
                    self.block_exec_command(
                        f"zfs destroy {zfs_filesystem}@{snapshot_name}",
                        False
                    )

    def close(self) -> None:
        ''' Scrubs the backup pool and then disconnects the SSH session '''
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


# pylint: disable-next=too-many-arguments
def send_log_via_mail(
    attachments: dict,
    send_from: str,
    send_to: list,
    subject: str,
    body: str,
    smtp_host: str,
    smtp_username: str,
    smtp_password: str
) -> None:
    ''' Send log file via e-mail '''
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

    except smtplib.SMTPResponseException as error:
        error_message = error.smtp_error
        logging.error("SMTP Error: %s", error_message)


def main_loop(config) -> None:
    ''' Main loop for the backup process '''
    while True:
        pve_agent_ = PVEAgent(**config["pvehost"])
        if pve_agent_.backup_drive_present() and \
                pve_agent_.backup_timestamp_outdated():
            logbuffer = io.StringIO()
            bufferhandler = logging.StreamHandler(logbuffer)
            logging.getLogger().addHandler(bufferhandler)
            pve_agent_.mount_drive_to_vm()
            zfs_agent_ = ZFSAgent(**config["zfshost"])
            for zfs_filesystem in zfs_agent_.zfs_filesystems():
                zfs_agent_.zfssync(zfs_filesystem)
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


def load_example_config() -> dict:
    ''' Load example config file '''
    config_path = files('vzesync').joinpath('../examples/config.json')
    return json.loads(config_path.read_text())


def main() -> None:
    ''' Main function to set up and run the backup process '''
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


if __name__ == "__main__":
    main()
