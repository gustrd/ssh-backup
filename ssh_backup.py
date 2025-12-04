import os
import sys
import subprocess
import tarfile
import shlex
import tempfile
import shutil
import traceback
import re
import argparse

CONFIG_FILE = ".ssh-backup_config.txt"
BACKUP_DIR = "ssh-backups"


def is_windows_path(path):
    """Check if a path is a Windows-style path."""
    return bool(re.match(r'^[A-Za-z]:[/\\]', path))


def is_absolute_path(path):
    r"""Check if a path is absolute (Unix or Windows format).

    Supports:
    - Unix paths: /home/user/data
    - Windows paths: C:\Users\data, D:/folder
    """
    # Unix absolute path
    if path.startswith('/'):
        return True
    # Windows absolute path
    return is_windows_path(path)


def normalize_path_for_tar(path):
    """Normalize a path for tar extraction lookup.

    Tar strips leading / from Unix paths.
    For Windows paths like C:\foo, tar stores them as C:/foo or similar.
    """
    # Unix path: strip leading /
    if path.startswith('/'):
        return path.lstrip('/')
    # Windows path: keep as-is but normalize separators
    # Tar typically converts backslashes to forward slashes
    return path.replace('\\', '/')


def path_to_slug(path):
    """Convert a path to a slug for directory naming.

    Handles both Unix and Windows paths.
    """
    # For Windows paths like C:\Users\data, remove the colon and normalize
    if is_windows_path(path):
        # C:\Users\data -> C_Users_data
        slug = path[0] + path[2:]  # Remove the colon
        slug = slug.replace('\\', '_').replace('/', '_')
        return slug.strip('_')
    else:
        # Unix path: /home/user/data -> home_user_data
        return path.strip('/').replace('/', '_')


def windows_path_to_wsl(path):
    """Convert a Windows path to WSL path.

    Example: C:\\_scripts -> /mnt/c/_scripts
    """
    # Match drive letter and path
    match = re.match(r'^([A-Za-z]):[/\\](.*)$', path)
    if match:
        drive = match.group(1).lower()
        rest = match.group(2).replace('\\', '/')
        return f"/mnt/{drive}/{rest}"
    return path


def parse_target_line(line):
    """Parse a target line from config file.
    
    Format: [user@]host:/path [use_sudo]
    Returns: (target_str, use_sudo) or (None, False) if invalid
    """
    line = line.strip()
    if not line:
        return None, False
    
    # Check for optional sudo flag at the end
    # Use rsplit to handle paths with spaces correctly
    parts = line.rsplit(None, 1)
    if len(parts) > 1 and parts[1].lower() in ('use_sudo', 'sudo'):
        target = parts[0]
        use_sudo = True
    else:
        target = line
        use_sudo = False
    
    return target, use_sudo

def validate_target(target):
    """Validate a backup target entry. Returns (is_valid, error_message)."""
    if not target:
        return False, "empty target"

    # Must contain exactly one colon separating host from path
    if ':' not in target:
        return False, "missing ':' separator (expected format: [user@]host:/path)"

    remote_part, path = target.split(':', 1)

    # Validate remote part (host or user@host)
    if not remote_part:
        return False, "missing host"

    if '@' in remote_part:
        user, host = remote_part.split('@', 1)
        if not user:
            return False, "empty username before '@'"
        if not host:
            return False, "empty hostname after '@'"

    # Validate path
    if not path:
        return False, "missing remote path"

    if not is_absolute_path(path):
        return False, f"path should be absolute (e.g., '/path' or 'C:\\path'), got: {path}"

    return True, None

def parse_config():
    """Parse and validate the configuration file.
    
    Returns list of tuples: [(target_string, use_sudo), ...]
    """
    if not os.path.exists(CONFIG_FILE):
        print(f"Error: Config file '{CONFIG_FILE}' not found.")
        sys.exit(1)

    targets = []
    errors = []
    line_num = 0

    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line_num += 1
            original_line = line.strip()
            if not original_line or original_line.startswith('#'):
                continue

            target, use_sudo = parse_target_line(original_line)
            if not target:
                errors.append(f"  Line {line_num}: empty target -> '{original_line}'")
                continue
                
            is_valid, error_msg = validate_target(target)
            if is_valid:
                targets.append((target, use_sudo))
            else:
                errors.append(f"  Line {line_num}: {error_msg} -> '{original_line}'")

    if errors:
        print(f"Error: Found {len(errors)} invalid entries in '{CONFIG_FILE}':")
        for err in errors:
            print(err)
        sys.exit(1)

    return targets

class SSHConfigError(Exception):
    """Raised when SSH configuration cannot be resolved."""
    pass


def get_remote_details(target):
    """Parse target and resolve SSH config using 'ssh -G'.

    Raises:
        SSHConfigError: If SSH config resolution fails or user cannot be determined.
    """
    remote_part, path = target.split(':', 1)

    if '@' in remote_part:
        user_part, host_alias = remote_part.split('@', 1)
        lookup_target = remote_part
    else:
        host_alias = remote_part
        user_part = None
        lookup_target = host_alias

    # Use ssh -G to resolve configuration (handles aliases, Includes, etc.)
    try:
        result = subprocess.run(
            ["ssh", "-G", lookup_target],
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        raise SSHConfigError(f"Failed to resolve SSH config for '{lookup_target}': {e}")

    # Parse ssh -G output
    config = {}
    for line in result.stdout.splitlines():
        if not line or line.startswith('#'):
            continue
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            key, value = parts
            # Validate that key contains only expected characters
            if key.isalnum():
                config[key.lower()] = value

    # Extract resolved details
    actual_host = config.get('hostname', host_alias)

    # Determine user - explicit user in target takes precedence
    if user_part:
        actual_user = user_part
    elif 'user' in config:
        actual_user = config['user']
    else:
        raise SSHConfigError(
            f"No user specified for '{target}' and none found in SSH config. "
            "Please specify user as 'user@host:/path' or configure it in ~/.ssh/config"
        )

    # Parse port with validation
    try:
        actual_port = int(config.get('port', 22))
    except ValueError:
        raise SSHConfigError(f"Invalid port value in SSH config for '{lookup_target}'")

    return actual_host, actual_user, actual_port, path


def group_targets_by_host(targets):
    """Group backup targets by host to minimize connections.

    Args:
        targets: List of (target_string, use_sudo) tuples

    Returns:
        Dictionary mapping (host, user, port) to list of (target, path, use_sudo) tuples

    Raises:
        SSHConfigError: If SSH config resolution fails for any target.
    """
    groups = {}
    for target, use_sudo in targets:
        host, user, port, path = get_remote_details(target)

        key = (host, user, port)
        if key not in groups:
            groups[key] = []
        groups[key].append((target, path, use_sudo))

    return groups

def check_wsl_available(host, user, port):
    """Check if WSL is available on a Windows remote host."""
    ssh_cmd = [
        "ssh",
        "-p", str(port),
        "-o", "ConnectTimeout=10",
        "-o", "BatchMode=yes",
        f"{user}@{host}",
        "wsl --list --quiet"
    ]
    try:
        result = subprocess.run(ssh_cmd, capture_output=True, timeout=15)
        # wsl --list returns 0 if WSL is installed with at least one distro
        return result.returncode == 0 and len(result.stdout.strip()) > 0
    except (subprocess.TimeoutExpired, Exception):
        return False


def process_backup_stream(process, paths_map, host):
    """Process the tar stream from the SSH process and organize files.

    Args:
        process: The subprocess.Popen object with stdout pipe.
        paths_map: List of (target, req_path, expected_rel_path) tuples.
        host: Hostname for directory naming.

    Returns:
        Tuple of (results_list, files_extracted_count) where results_list contains (target, success_bool)
    """
    results = []
    files_extracted = 0

    with tempfile.TemporaryDirectory() as temp_dir:
        # Extract tar stream
        tar_errors = []
        try:
            with tarfile.open(fileobj=process.stdout, mode="r|") as tar:
                for member in tar:
                    # Security: skip symlinks entirely to prevent symlink attacks
                    if member.issym() or member.islnk():
                        print(f"  ! Skipping symlink: {member.name}")
                        continue

                    # Security: prevent path traversal attacks
                    member_path = os.path.normpath(member.name)
                    if member_path.startswith('..') or os.path.isabs(member_path):
                        print(f"  ! Skipping suspicious path: {member.name}")
                        continue

                    # Verify the resolved path stays within temp_dir
                    dest_path = os.path.realpath(os.path.join(temp_dir, member_path))
                    if not dest_path.startswith(os.path.realpath(temp_dir)):
                        print(f"  ! Skipping path escape attempt: {member.name}")
                        continue

                    # Extract without following symlinks
                    tar.extract(member, path=temp_dir, set_attrs=True)
                    files_extracted += 1
        except tarfile.ReadError as e:
            tar_errors.append(str(e))

        process.wait()

        # Show stderr if there were issues
        stderr = process.stderr.read().decode().strip()
        if stderr:
            # Filter out common tar warnings
            for line in stderr.split('\n'):
                if line and 'Removing leading' not in line:
                    print(f"  [!] {line}")

        if process.returncode == 255:
            print(f"  [X] SSH connection failed")
            return [(t, False) for t, _, _ in paths_map], 0

        # Organize extracted files
        for target, req_path, expected_rel_path in paths_map:
            source_path = os.path.join(temp_dir, expected_rel_path)

            if not os.path.exists(source_path):
                print(f"  [X] Warning: {req_path} not found in backup stream")
                if tar_errors:
                    print(f"      Tar errors: {tar_errors}")
                results.append((target, False))
                continue

            # Organize to destination
            slug = path_to_slug(req_path)

            try:
                if os.path.isdir(source_path):
                    dest_path = os.path.join(BACKUP_DIR, f"{host}_{slug}")
                    if os.path.exists(dest_path):
                        shutil.rmtree(dest_path)
                    # Don't preserve symlinks - copy actual content only
                    shutil.copytree(source_path, dest_path, dirs_exist_ok=True, symlinks=False)
                else:
                    parent_dir = os.path.dirname(req_path)
                    parent_slug = path_to_slug(parent_dir) if parent_dir else ""
                    dest_folder = os.path.join(BACKUP_DIR, f"{host}_{parent_slug}" if parent_slug else host)
                    os.makedirs(dest_folder, exist_ok=True)
                    dest_path = os.path.join(dest_folder, os.path.basename(req_path))
                    if os.path.exists(dest_path):
                        os.remove(dest_path)
                    shutil.copy2(source_path, dest_path)
            except (OSError, shutil.Error) as e:
                print(f"  [X] Error writing {req_path}: {e}")
                results.append((target, False))
                continue

            print(f"  [OK] {target} -> {dest_path}")
            results.append((target, True))

    return results, files_extracted


def backup_windows_host(host, user, port, paths, dry_run=False):
    """Backup paths from a Windows host using WSL tar.

    Windows paths are converted to WSL paths (e.g., C:\\_scripts -> /mnt/c/_scripts)
    and tar is run via WSL to create a stream.

    Returns:
        Tuple of (results_list, files_extracted_count)
    """
    # Check WSL availability first
    if not dry_run:
        print("  Checking WSL availability...")
        if not check_wsl_available(host, user, port):
            print("  [X] WSL is not available on the remote Windows host.")
            print("      Please ensure WSL is installed and a Linux distribution is set up.")
            return [(target, False) for target, _, _ in paths], 0

    # Convert Windows paths to WSL paths and get the base directory
    wsl_paths = []
    for target, req_path, use_sudo in paths:
        wsl_path = windows_path_to_wsl(req_path)
        # Get base dir and relative path for tar -C
        # e.g., /mnt/c/_scripts -> base=/mnt/c, rel=_scripts
        parts = wsl_path.rstrip('/').rsplit('/', 1)
        if len(parts) == 2:
            base_dir, rel_path = parts
        else:
            base_dir, rel_path = '/', wsl_path.lstrip('/')
        wsl_paths.append((target, req_path, base_dir, rel_path, use_sudo))

    results = []
    total_files = 0

    for target, req_path, base_dir, rel_path, use_sudo in wsl_paths:
        if dry_run:
            sudo_marker = " (with sudo)" if use_sudo else ""
            print(f"  [DRY-RUN] Would backup {req_path}{sudo_marker}")
            results.append((target, True))
            continue

        sudo_marker = " (with sudo)" if use_sudo else ""
        print(f"  Backing up {req_path}{sudo_marker}...")

        # Build WSL tar command safely
        # Use shlex.quote to prevent command injection
        sudo_prefix = "sudo " if use_sudo else ""

        # Construct the inner tar command
        # We use 'sh -c' inside WSL to handle the command string
        # The inner command must be properly quoted for the shell inside WSL
        inner_cmd = f"{sudo_prefix}tar -C {shlex.quote(base_dir)} -chf - {shlex.quote(rel_path)}"

        # The outer command invokes WSL
        # We quote the inner command for the SSH shell
        wsl_cmd = f"wsl sh -c {shlex.quote(inner_cmd)}"

        ssh_cmd = [
            "ssh",
            "-p", str(port),
            "-o", "ConnectTimeout=30",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
            "-o", "BatchMode=yes",
            f"{user}@{host}",
            wsl_cmd
        ]

        try:
            process = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            # Map for this single file backup
            # (target, original_req_path, expected_rel_path_in_tar)
            paths_map = [(target, req_path, rel_path)]

            batch_results, files = process_backup_stream(process, paths_map, host)
            results.extend(batch_results)
            total_files += files

        except Exception as e:
            print(f"  [X] Error backing up {req_path}: {e}")
            traceback.print_exc()
            results.append((target, False))

    return results, total_files


def _run_unix_backup_batch(host, user, port, paths_batch, use_sudo):
    """Run a single tar backup batch for Unix host.

    Args:
        host: Remote hostname
        user: SSH username
        port: SSH port
        paths_batch: List of (target, req_path, use_sudo) tuples
        use_sudo: Whether to use sudo for this batch

    Returns:
        Tuple of (results_list, files_extracted_count)
    """
    remote_paths = [p for _, p, _ in paths_batch]
    quoted_paths = [shlex.quote(p) for p in remote_paths]

    sudo_prefix = "sudo " if use_sudo else ""
    tar_cmd_str = f"{sudo_prefix}tar cf - {' '.join(quoted_paths)}"

    ssh_cmd = [
        "ssh",
        "-p", str(port),
        "-o", "ConnectTimeout=30",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
        "-o", "BatchMode=yes",
        f"{user}@{host}",
        tar_cmd_str
    ]

    sudo_marker = " (with sudo)" if use_sudo else ""
    print(f"Downloading {len(remote_paths)} items{sudo_marker} in a single stream...")

    try:
        process = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Prepare paths map for processing
        paths_map = []
        for target, req_path, _ in paths_batch:
            rel_req_path = normalize_path_for_tar(req_path)
            paths_map.append((target, req_path, rel_req_path))

        return process_backup_stream(process, paths_map, host)

    except Exception as e:
        print(f"Error processing stream: {e}")
        traceback.print_exc()
        return [(t, False) for t, _, _ in paths_batch], 0


def backup_unix_host(host, user, port, paths, dry_run=False):
    """Backup paths from a Unix host using tar.

    Paths are grouped by sudo requirement to ensure sudo is only used
    for paths that explicitly request it.
    """
    if dry_run:
        for target, req_path, use_sudo in paths:
            sudo_marker = " (with sudo)" if use_sudo else ""
            print(f"  [DRY-RUN] Would backup {req_path}{sudo_marker}")
        return [(target, True) for target, _, _ in paths], 0

    # Group paths by sudo requirement for consistent handling
    sudo_paths = [(t, p, s) for t, p, s in paths if s]
    normal_paths = [(t, p, s) for t, p, s in paths if not s]

    all_results = []
    total_files = 0

    # Process normal paths first
    if normal_paths:
        results, files = _run_unix_backup_batch(host, user, port, normal_paths, use_sudo=False)
        all_results.extend(results)
        total_files += files

    # Process sudo paths separately
    if sudo_paths:
        results, files = _run_unix_backup_batch(host, user, port, sudo_paths, use_sudo=True)
        all_results.extend(results)
        total_files += files

    return all_results, total_files


def backup_host_group(host, user, port, paths, dry_run=False):
    """Backup all paths for a single host using appropriate method based on OS.

    Returns:
        Tuple of (results_list, files_extracted_count)
    """
    print(f"\n{'='*60}")
    print(f"Connecting to {user}@{host}:{port}")
    print(f"{'='*60}\n")

    # Check if any path is Windows-style to determine backup method
    has_windows_paths = any(is_windows_path(p) for _, p, _ in paths)

    if has_windows_paths:
        print("Detected Windows remote, using WSL tar backup method...")
        return backup_windows_host(host, user, port, paths, dry_run)
    else:
        return backup_unix_host(host, user, port, paths, dry_run)

def main():
    parser = argparse.ArgumentParser(
        description="Backup files from remote SSH hosts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ssh_backup.py              # Run backup
  python ssh_backup.py --dry-run    # Preview what would be backed up
  python ssh_backup.py -n           # Same as --dry-run
        """
    )
    parser.add_argument(
        '-n', '--dry-run',
        action='store_true',
        help='Show what would be backed up without actually doing it'
    )
    args = parser.parse_args()

    if args.dry_run:
        print("=" * 60)
        print("DRY-RUN MODE - No files will be transferred")
        print("=" * 60)

    if not args.dry_run and not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)

    targets = parse_config()
    if not targets:
        print(f"Error: No backup targets found in '{CONFIG_FILE}'.")
        sys.exit(1)

    print(f"Found {len(targets)} backup targets.")

    # Group by host
    try:
        groups = group_targets_by_host(targets)
    except SSHConfigError as e:
        print(f"Error: {e}")
        sys.exit(1)

    print(f"Grouped into {len(groups)} host(s).\n")

    all_results = []
    total_files_extracted = 0

    # Process each host group
    for (host, user, port), paths in groups.items():
        results, files_extracted = backup_host_group(host, user, port, paths, dry_run=args.dry_run)
        all_results.extend(results)
        total_files_extracted += files_extracted

    # Summary
    completed = sum(1 for _, success in all_results if success)
    failed = len(all_results) - completed

    print(f"\n{'='*60}")
    if args.dry_run:
        print("DRY-RUN SUMMARY")
    else:
        print("BACKUP SUMMARY")
    print(f"{'='*60}")
    print(f"Targets completed: {completed}/{len(all_results)}")
    if not args.dry_run:
        print(f"Files extracted: {total_files_extracted}")
    print(f"Failed: {failed}")

    if failed > 0:
        print("\nFailures:")
        for target, success in all_results:
            if not success:
                print(f"  - {target}")

    # Integrity check: warn if no files were extracted for successful targets
    if not args.dry_run and completed > 0 and total_files_extracted == 0:
        print("\n[!] WARNING: No files were extracted despite successful connections.")
        print("    This may indicate empty directories or permission issues.")

    print(f"{'='*60}\n")

    # Return non-zero exit code if there were failures
    if failed > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
