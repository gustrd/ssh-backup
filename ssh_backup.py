import os
import sys
import subprocess
import tarfile
import shlex
import tempfile
import shutil
import traceback

CONFIG_FILE = ".ssh-backup_config.txt"
BACKUP_DIR = "ssh-backups"

def validate_target(target, line_num):
    """Validate a backup target entry. Returns (is_valid, error_message)."""
    if not target:
        return False, "empty target"

    # Must contain exactly one colon separating host from path
    if ':' not in target:
        return False, "missing ':' separator (expected format: [user@]host:/path)"

    parts = target.split(':', 1)
    if len(parts) != 2:
        return False, "invalid format (expected format: [user@]host:/path)"

    remote_part, path = parts

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

    if not path.startswith('/'):
        return False, f"path should be absolute (starts with '/'), got: {path}"

    return True, None

def parse_config():
    """Parse and validate the configuration file."""
    if not os.path.exists(CONFIG_FILE):
        print(f"Error: Config file '{CONFIG_FILE}' not found.")
        sys.exit(1)

    targets = []
    errors = []
    line_num = 0

    with open(CONFIG_FILE, 'r') as f:
        for line in f:
            line_num += 1
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            is_valid, error_msg = validate_target(line, line_num)
            if is_valid:
                targets.append(line)
            else:
                errors.append(f"  Line {line_num}: {error_msg} -> '{line}'")

    if errors:
        print(f"Error: Found {len(errors)} invalid entries in '{CONFIG_FILE}':")
        for err in errors:
            print(err)
        sys.exit(1)

    if not targets:
        print(f"Warning: No backup targets found in '{CONFIG_FILE}'.")

    return targets

def get_remote_details(target):
    """Parse target and resolve SSH config"""
    try:
        remote_part, path = target.split(':', 1)
        
        # Simple SSH config parsing (no paramiko)
        ssh_config_file = os.path.expanduser("~/.ssh/config")
        host_config = {}
        
        if '@' not in remote_part:
            host_alias = remote_part
            if os.path.exists(ssh_config_file):
                try:
                    with open(ssh_config_file, 'r') as f:
                        in_host_block = False
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue
                            
                            parts = line.split(maxsplit=1)
                            key = parts[0].lower()
                            value = parts[1] if len(parts) > 1 else ""
                            
                            if key == 'host':
                                # Check if this block matches our alias
                                aliases = value.split()
                                if host_alias in aliases:
                                    in_host_block = True
                                else:
                                    in_host_block = False
                            elif in_host_block:
                                if key == 'hostname':
                                    host_config['hostname'] = value
                                elif key == 'user':
                                    host_config['user'] = value
                                elif key == 'port':
                                    host_config['port'] = value
                except Exception as e:
                    print(f"Warning: Failed to parse SSH config for '{host_alias}': {e}")
        
        if '@' in remote_part:
            user, host_alias = remote_part.split('@', 1)
        else:
            host_alias = remote_part
            user = host_config.get('user', os.getenv('USER', 'ubuntu'))
        
        # Get actual hostname and port from config
        actual_host = host_config.get('hostname', host_alias)
        actual_port = int(host_config.get('port', 22))
        
        return actual_host, user, actual_port, path
    except ValueError as e:
        print(f"Error: Invalid target format '{target}': {e}")
        return None, None, None, None


def group_targets_by_host(targets):
    """Group backup targets by host to minimize connections"""
    groups = {}
    for target in targets:
        host, user, port, path = get_remote_details(target)
        if not host:
            continue
        
        key = (host, user, port)
        if key not in groups:
            groups[key] = []
        groups[key].append((target, path))
    
    return groups

def backup_host_group(host, user, port, paths):
    """Backup all paths for a single host using a single SSH connection and tar stream"""
    print(f"\n{'='*60}")
    print(f"Connecting to {user}@{host}:{port}")
    print(f"{'='*60}\n")
    
    remote_paths = [p for _, p in paths]
    quoted_paths = [shlex.quote(p) for p in remote_paths]
    # Use -h to dereference symlinks (optional, but good for backups)
    tar_cmd_str = f"tar chf - {' '.join(quoted_paths)} 2>/dev/null"
    
    ssh_cmd = [
        "ssh",
        "-p", str(port),
        f"{user}@{host}",
        tar_cmd_str
    ]
    
    print(f"Downloading {len(remote_paths)} items in a single stream...")

    # Create a temp directory to extract the full structure
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            # Run SSH and pipe directly to tar extraction in the temp dir
            # We use subprocess to pipe ssh stdout to tar stdin
            
            # Windows tar might behave differently, so let's use python's tarfile module
            # We'll pipe SSH stdout to Python
            
            process = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Extract to temp_dir with path traversal protection
            with tarfile.open(fileobj=process.stdout, mode="r|") as tar:
                for member in tar:
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
                    tar.extract(member, path=temp_dir)
            
            process.wait()
            
            if process.returncode != 0:
                # Check if it was just warnings (tar returns 1 for file changed as we read it)
                # But we suppressed stderr on remote.
                # If ssh failed, returncode would be 255.
                if process.returncode == 255:
                    print("SSH Connection failed.")
                    return [(t, False) for t, _ in paths]
            
            print("✓ Download complete. Organizing files...")
            
            # Now move files from temp_dir to BACKUP_DIR with correct naming
            results = []
            for target, req_path in paths:
                # The file/dir is at temp_dir + req_path (because tar preserves full path)
                # e.g. temp_dir/home/ubuntu/.bashrc
                
                # Note: tar usually strips leading /
                rel_req_path = req_path.lstrip('/')
                source_path = os.path.join(temp_dir, rel_req_path)
                
                if not os.path.exists(source_path):
                    print(f"  ✗ Warning: {req_path} not found in backup stream")
                    results.append((target, False))
                    continue
                
                # Determine destination
                if os.path.isdir(source_path):
                    # It's a directory
                    # Destination: ssh-backups/host_path_slug
                    slug = req_path.strip('/').replace('/', '_')
                    dest_path = os.path.join(BACKUP_DIR, f"{host}_{slug}")
                    
                    # Move content
                    if os.path.exists(dest_path):
                        shutil.rmtree(dest_path)
                    
                    # shutil.move(source_path, dest_path) 
                    # But source_path is inside temp_dir, we can just move it
                    # However, we want the CONTENTS of source_path to be in dest_path?
                    # Or dest_path IS the directory?
                    # Previous logic: ssh-backups/host_scripts/ (contains script files)
                    # source_path is .../scripts/
                    
                    # So we move source_path to dest_path
                    shutil.copytree(source_path, dest_path, dirs_exist_ok=True)
                    
                else:
                    # It's a file
                    # Destination: ssh-backups/host_parent_slug/filename
                    parent_dir = os.path.dirname(req_path)
                    slug = parent_dir.strip('/').replace('/', '_')
                    dest_folder = os.path.join(BACKUP_DIR, f"{host}_{slug}")
                    os.makedirs(dest_folder, exist_ok=True)
                    
                    dest_path = os.path.join(dest_folder, os.path.basename(req_path))
                    
                    if os.path.exists(dest_path):
                        os.remove(dest_path)
                    shutil.copy2(source_path, dest_path)
                
                print(f"  ✓ {target} -> {dest_path}")
                results.append((target, True))
                
            return results
            
        except Exception as e:
            print(f"Error processing stream: {e}")
            traceback.print_exc()
            return [(t, False) for t, _ in paths]

def main():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    
    targets = parse_config()
    print(f"Found {len(targets)} backup targets.")
    
    # Group by host
    groups = group_targets_by_host(targets)
    print(f"Grouped into {len(groups)} host(s).\n")
    
    all_results = []
    
    # Process each host group
    for (host, user, port), paths in groups.items():
        results = backup_host_group(host, user, port, paths)
        all_results.extend(results)
    
    # Summary
    completed = sum(1 for _, success in all_results if success)
    failed = len(all_results) - completed
    
    print(f"\n{'='*60}")
    print("BACKUP SUMMARY")
    print(f"{'='*60}")
    print(f"Completed: {completed}")
    print(f"Failed: {failed}")
    
    if failed > 0:
        print("\nFailures:")
        for target, success in all_results:
            if not success:
                print(f"  - {target}")
    
    print(f"{'='*60}\n")

if __name__ == "__main__":
    main()
