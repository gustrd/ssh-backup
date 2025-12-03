import os
import sys
import subprocess
import tarfile
import io
import shlex

CONFIG_FILE = ".ssh-backup_config.txt"
BACKUP_DIR = "ssh-backups"

def parse_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"Error: Config file '{CONFIG_FILE}' not found.")
        sys.exit(1)
    targets = []
    with open(CONFIG_FILE, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                targets.append(line)
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
                except Exception:
                    pass # Ignore config parsing errors
        
        if '@' in remote_part:
            user, host_alias = remote_part.split('@', 1)
        else:
            host_alias = remote_part
            user = host_config.get('user', os.getenv('USER', 'ubuntu'))
        
        # Get actual hostname and port from config
        actual_host = host_config.get('hostname', host_alias)
        actual_port = int(host_config.get('port', 22))
        
        return actual_host, user, actual_port, path
    except ValueError:
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
    
    # Construct the tar command to run on the server
    # We use 'tar cf - path1 path2 ...' to stream the tarball to stdout
    # We use --ignore-failed-read to skip files we can't read (permission denied)
    # We quote paths to handle spaces
    
    remote_paths = [p for _, p in paths]
    quoted_paths = [shlex.quote(p) for p in remote_paths]
    tar_cmd_str = f"tar cf - {' '.join(quoted_paths)} 2>/dev/null"
    
    ssh_cmd = [
        "ssh",
        "-p", str(port),
        f"{user}@{host}",
        tar_cmd_str
    ]
    
    print(f"Downloading {len(remote_paths)} items in a single stream...")
    
    try:
        # Run SSH and capture stdout (the tar stream)
        # We use a large buffer size for performance
        process = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Read the tar stream from stdout
        # We use tarfile to extract on the fly
        # But we need to map the extracted files to our desired destination structure
        
        # Our desired structure:
        # ssh-backups/host_path_slug/contents
        
        # The tar stream contains paths relative to root (e.g., home/ubuntu/.ssh/authorized_keys)
        # We need to intercept the extraction and redirect to the correct local folder
        
        # Since we can't easily "redirect" inside tarfile.extractall without extracting to a temp dir first,
        # let's extract to a temp dir and then move.
        # OR, we can iterate over members and extract them one by one to the right place.
        
        # Let's try iterating members from the stream
        with tarfile.open(fileobj=process.stdout, mode="r|") as tar:
            for member in tar:
                # Find which target this member belongs to
                # member.name is the path inside the tar (e.g. home/ubuntu/.ssh/id_rsa)
                # We need to match it against our requested paths
                
                # Normalize member name (remove leading / if present, though tar usually removes it)
                member_path = "/" + member.name.lstrip("/")
                
                # Find the best matching target path (longest prefix match)
                best_match = None
                best_match_len = -1
                
                for target, req_path in paths:
                    # Check if member_path starts with req_path
                    # Handle directory match: req_path=/home/ubuntu/scripts, member=/home/ubuntu/scripts/foo.sh
                    # Handle file match: req_path=/home/ubuntu/.bashrc, member=/home/ubuntu/.bashrc
                    
                    # Ensure trailing slash for dir check to avoid partial name match
                    req_dir = req_path if req_path.endswith('/') else req_path + '/'
                    
                    if member_path == req_path or member_path.startswith(req_dir):
                        if len(req_path) > best_match_len:
                            best_match = (target, req_path)
                            best_match_len = len(req_path)
                
                if best_match:
                    target_name, req_path = best_match
                    
                    # Determine destination
                    # Dir: ssh-backups/host_path_slug/relative_part
                    # File: ssh-backups/host_parent_slug/filename
                    
                    # We need to know if the requested path was a directory or file
                    # But we don't know for sure without checking remote.
                    # However, if the member path is longer than req_path, req_path was a dir.
                    # If they are equal, it could be a file or a dir (but tar usually adds trailing slash for dirs? no)
                    
                    # Let's stick to the naming convention:
                    # ssh-backups/host_path_slug
                    
                    slug = req_path.strip('/').replace('/', '_')
                    if not slug: slug = "root"
                    
                    # If we treat everything as a "folder" in our backup structure:
                    # /home/ubuntu/.bashrc -> ssh-backups/host_home_ubuntu_.bashrc/.bashrc ?
                    # No, the user wanted:
                    # /home/ubuntu/.bashrc -> ssh-backups/host_home_ubuntu/.bashrc
                    # /home/ubuntu/scripts -> ssh-backups/host_home_ubuntu_scripts/script1.sh
                    
                    # Let's try to reconstruct the destination path
                    
                    # Logic:
                    # 1. Calculate the relative path of the member from the requested path
                    #    req=/a/b, member=/a/b/c -> rel=c
                    #    req=/a/b, member=/a/b -> rel=""
                    
                    if member_path == req_path:
                        rel_path = os.path.basename(req_path)
                        # Parent of requested path
                        parent_req = os.path.dirname(req_path)
                        slug_base = parent_req.strip('/').replace('/', '_')
                        dest_root = os.path.join(BACKUP_DIR, f"{host}_{slug_base}")
                    else:
                        # It's a file inside a requested directory
                        rel_path = member_path[len(req_path):].lstrip('/')
                        slug_base = req_path.strip('/').replace('/', '_')
                        dest_root = os.path.join(BACKUP_DIR, f"{host}_{slug_base}")
                        
                        # If it was a directory request, we want the structure preserved
                        # But wait, if I request /home/ubuntu/scripts
                        # and get /home/ubuntu/scripts/foo.sh
                        # I want ssh-backups/host_home_ubuntu_scripts/foo.sh
                        
                        # So:
                        # dest_root = ssh-backups/host_home_ubuntu_scripts
                        # final_path = dest_root / foo.sh
                        
                        # But what if I request a file /home/ubuntu/.bashrc?
                        # member = /home/ubuntu/.bashrc
                        # I want ssh-backups/host_home_ubuntu/.bashrc
                        
                        # Let's simplify:
                        # If member matches req_path exactly, is it a file or dir?
                        # If it's a file, we want it in host_parent_slug
                        # If it's a dir, we want it in host_path_slug (and contents inside)
                        
                        # Since we are extracting a stream, we can just dump everything to a temp dir
                        # and then move/organize. That might be safer and easier.
                        pass

        # Wait for process to finish
        process.wait()
        
        if process.returncode != 0:
            stderr = process.stderr.read().decode()
            print(f"SSH Error: {stderr}")
            return [(t, False) for t, _ in paths]
            
        print("✓ Stream received successfully. Organizing files...")
        
        # Re-run the extraction logic properly now that we know the stream works
        # Actually, we consumed the stream above. We need to do it in one pass.
        # Since the logic above was complex to do on-the-fly, let's use the "extract to temp" approach.
        # But we can't seek on a pipe.
        
        # Let's restart the approach:
        # 1. Stream tar to a temporary file (so we can seek/read multiple times if needed, or just extract)
        # 2. Extract everything to a temp directory
        # 3. Move files to their final destinations
        
    except Exception as e:
        print(f"Error: {e}")
        return [(t, False) for t, _ in paths]

    return [] # Placeholder

def backup_host_group_v2(host, user, port, paths):
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
    
    import tempfile
    import shutil
    
    # Create a temp directory to extract the full structure
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            # Run SSH and pipe directly to tar extraction in the temp dir
            # We use subprocess to pipe ssh stdout to tar stdin
            
            # Windows tar might behave differently, so let's use python's tarfile module
            # We'll pipe SSH stdout to Python
            
            process = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Extract to temp_dir
            with tarfile.open(fileobj=process.stdout, mode="r|") as tar:
                tar.extractall(path=temp_dir)
            
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
            import traceback
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
        results = backup_host_group_v2(host, user, port, paths)
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
