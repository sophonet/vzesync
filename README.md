# Automating backups via zfs send/recv on a Proxmox Linux VM

## Introduction

On my personal home server I am running an encrypted zfs raid1 for storing all personal
data (NAS). The server host is running proxmox and the server itself is running as a Debian
VM. The two zfs raid1 disks are passed through the VM, so the ZFS modules need to be
available in the VM (see ee e.g. https://openzfs.github.io/openzfs-docs/Getting%20Started/Debian/index.html
and additional hints for UEFI boot https://forums.debian.net/viewtopic.php?t=154555:).

This explains the acronym "Virtual host with ZFS-Encryption".

The container-based backup service in this repository does the following:

* The service checks the presence of attached backup disks on the proxmox host once an hour
* If a backup disk has been attached later than the last backup for that machine,
  all non top-level zfs filesystems are backed up via snapshots and zfs send/recv.
  If the backup disk does not contain backup snapshots, a full sync is done
* After finishing the backup job, the zfs disk is scrubbed to ensure consistency, exported, and
  (after that) is disconnected from the server VM and a notification e-mail is sent.

Therefore, the backup service runs fully automatic and just requires plugging in a disk and
unplugging it after notification. Since zfs snapshots are fast, there is no downtime for
the services running on the server VM (including e.g. smart home etc.).

Security note: This service accesses both the Proxmox host and the Server VM as a root user (with SSH keys).
Please check the python code in case of doubt.

# Prerequisites

* A running ZFS infrastructure in a virtual machine.

# Installation

The steps below describe manual installation. However, it can be automated using ansible and the
role implemented here https://github.com/sophonet/vzesync-role.

1. Check out this repository to a folder of choice in the server VM, e.g. in an encrypted filesystem
   on the ZFS raid (since it will later include an SMTP password).
2. Copy config.json.template to config.json and change its content. In particular:
   - For the notification e-mail: smtp user, password as well as e-mail user and receiver address
   - For accessing the Proxmox host and checking the presence of attached backup disks:
       - The proxmox host IP address and private root key such that service can log in
       - The proxmox host key (```ssh-keyscan PROXMOXHOST```), pick one of the results
       - A dictionary mapping device names of all backup disks that shall be used in
         /dev/disk/by-id to a meaningful name
       - The VM ID and SCSI device to which the backup disk shall be passed through
    - For accessing the server VM and running zfs send/recv commands:
        - The server VM's IP address and private root key
        - The server's host key (```ssh-keyscan SERVERVM```), pick one of the results
        - The name of the backup pool and root fs on the pool
        - Number of snapshots on the backup drive that should be kept, per top filesystem
3. Build the container with (python + paramiko) with ```docker compose build```
3. Copy vzesync.service to /etc/systemd/system, adjust the WorkingDirectory and run
```
systemctl daemon-reload
systemctl enable --now vzesync
```

# Preparing a zfs backup disk

1. Attach a new backup disk manually to the VM on the Proxmox host (example below with scsi4, choose another device if better, make sure that IDENTIFIER is listed in config.json) with

```
qm set 100 -scsi4 /dev/disk/by-id/IDENTIFIER
```
2. Create a zpool and an encrypted/compressed top-level file system in the VM. The following commands assume that there is a password
key file available in a shared memory file on the server VM (only persistent until reboot, see https://github.com/sophonet/vzekeyprovider):
```
zpool create -f -o ashift=12 -m /zfs/backup backuppool /dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi4
zfs create -o dedup=off -o compression=zstd -o encryption=on -o keylocation=file:///dev/shm/zfspwd -o keyformat=passphrase backuppool/root
```
3. You are all set and can remove the prepared backup disk by running
```
zpool export backuppool # on the server VM
qm set 100  --delete scsi4 # afterwards, on PVE host
```
