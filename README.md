# SSH Backup Tool

A robust, cross-platform Python script designed to backup remote files and directories via SSH. It is specifically optimized for **FIDO/YubiKey** users and **Windows** environments, solving the common "multiple authentication prompts" issue by streaming all data through a single SSH connection per host.

## Features

- **FIDO/Windows Hello Friendly**: Authenticates once per host, then streams all requested files in a single pass. No more tapping your key 50 times for 50 files.
- **Cross-Platform**: Works seamlessly on Windows (using native OpenSSH) and Linux/macOS.
- **SSH Config Support**: Automatically resolves aliases, users, and ports from your `~/.ssh/config`.
- **Smart Organization**: Preserves remote directory structures locally with clean, readable naming conventions.
- **Zero Dependencies**: Uses standard system tools (`ssh`, `tar`) and Python standard library only.


## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/gustrd/ssh-backup.git
   cd ssh-backup
   ```

2. Ensure you have Python 3 installed.


## Configuration

1. Create a config file named `.ssh-backup_config.txt` in the script directory.
2. Add your backup targets, one per line.

**Format:**
```text
[user@]host:/remote/path/to/file_or_folder
```

**Example:**
```text
# Server 1 (using SSH config alias)
oracle-br:/home/ubuntu/.bashrc
oracle-br:/home/ubuntu/scripts

# Server 2 (explicit connection details)
admin@192.168.1.50:/var/www/html
```

## Usage

Run the script:

```bash
python ssh_backup.py
```

The script will:
1. Group targets by host.
2. Open **one** SSH connection to each host (prompting for FIDO PIN/Touch if needed).
3. Stream all requested files into a temporary local archive.
4. Extract and organize them into the `ssh-backups/` directory.

## Output Structure

Backups are saved in `ssh-backups/` with the following naming convention:

- **Files**: `hostname_parentdir_slug/filename`
- **Directories**: `hostname_fullpath_slug/`

**Example:**
- Remote: `oracle-br:/home/ubuntu/.bashrc`
- Local: `ssh-backups/oracle-br_home_ubuntu/.bashrc`

- Remote: `oracle-br:/home/ubuntu/scripts/`
- Local: `ssh-backups/oracle-br_home_ubuntu_scripts/`

## Troubleshooting

- **"Permission denied"**: Ensure your SSH key is loaded (`ssh-add -l`) or that you have configured `~/.ssh/config` correctly.
- **Windows Paths**: The script handles Windows paths automatically. Ensure you have the OpenSSH Client feature installed on Windows (Settings > Apps > Optional Features).

## License

MIT License
