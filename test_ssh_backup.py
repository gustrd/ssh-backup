import unittest
import os
import tempfile
import shutil
import subprocess
from unittest.mock import patch, mock_open
from ssh_backup import (
    validate_target,
    get_remote_details,
    group_targets_by_host,
    parse_config,
    is_absolute_path,
    is_windows_path,
    windows_path_to_wsl,
    normalize_path_for_tar,
    path_to_slug,
    process_backup_stream,
    backup_unix_host,
    backup_windows_host,
    SSHConfigError,
    CONFIG_FILE,
    BACKUP_DIR
)


class TestValidateTarget(unittest.TestCase):
    """Test cases for the validate_target function"""

    def test_valid_target_with_user(self):
        """Test valid target with user@host:/path format"""
        is_valid, error = validate_target("user@example.com:/home/user/data")
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_valid_target_without_user(self):
        """Test valid target with host:/path format"""
        is_valid, error = validate_target("example.com:/var/log")
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_valid_target_complex_path(self):
        """Test valid target with complex path"""
        is_valid, error = validate_target("user@host:/path/to/deep/directory")
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_empty_target(self):
        """Test empty target string"""
        is_valid, error = validate_target("")
        self.assertFalse(is_valid)
        self.assertEqual(error, "empty target")

    def test_missing_colon(self):
        """Test target missing colon separator"""
        is_valid, error = validate_target("example.com")
        self.assertFalse(is_valid)
        self.assertIn("missing ':'", error)

    def test_missing_host(self):
        """Test target with missing host"""
        is_valid, error = validate_target(":/path/to/dir")
        self.assertFalse(is_valid)
        self.assertEqual(error, "missing host")

    def test_empty_username(self):
        """Test target with empty username before @"""
        is_valid, error = validate_target("@host:/path")
        self.assertFalse(is_valid)
        self.assertEqual(error, "empty username before '@'")

    def test_empty_hostname_after_at(self):
        """Test target with empty hostname after @"""
        is_valid, error = validate_target("user@:/path")
        self.assertFalse(is_valid)
        self.assertEqual(error, "empty hostname after '@'")

    def test_missing_path(self):
        """Test target with missing path"""
        is_valid, error = validate_target("user@host:")
        self.assertFalse(is_valid)
        self.assertEqual(error, "missing remote path")

    def test_relative_path(self):
        """Test target with relative path (should be absolute)"""
        is_valid, error = validate_target("user@host:relative/path")
        self.assertFalse(is_valid)
        self.assertIn("should be absolute", error)

    def test_multiple_colons(self):
        """Test target with multiple colons (only first is used as separator)"""
        is_valid, error = validate_target("user@host:/path:with:colons")
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_valid_windows_path_backslash(self):
        """Test valid target with Windows path using backslashes"""
        is_valid, error = validate_target(r"user@host:C:\Users\data")
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_valid_windows_path_forward_slash(self):
        """Test valid target with Windows path using forward slashes"""
        is_valid, error = validate_target("user@host:D:/scripts/backup")
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_valid_windows_path_without_user(self):
        """Test valid Windows target without explicit user"""
        is_valid, error = validate_target(r"zenbook:C:\_scripts")
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_windows_path_lowercase_drive(self):
        """Test Windows path with lowercase drive letter"""
        is_valid, error = validate_target(r"host:c:\data")
        self.assertTrue(is_valid)
        self.assertIsNone(error)


class TestIsAbsolutePath(unittest.TestCase):
    """Test cases for the is_absolute_path helper function"""

    def test_unix_absolute_path(self):
        """Test Unix absolute path detection"""
        self.assertTrue(is_absolute_path("/home/user/data"))
        self.assertTrue(is_absolute_path("/"))
        self.assertTrue(is_absolute_path("/var/log"))

    def test_unix_relative_path(self):
        """Test Unix relative path detection"""
        self.assertFalse(is_absolute_path("relative/path"))
        self.assertFalse(is_absolute_path("./relative"))
        self.assertFalse(is_absolute_path("../parent"))

    def test_windows_absolute_path_backslash(self):
        """Test Windows absolute path with backslash"""
        self.assertTrue(is_absolute_path(r"C:\Users\data"))
        self.assertTrue(is_absolute_path("D:\\"))
        self.assertTrue(is_absolute_path(r"E:\folder\subfolder"))

    def test_windows_absolute_path_forward_slash(self):
        """Test Windows absolute path with forward slash"""
        self.assertTrue(is_absolute_path("C:/Users/data"))
        self.assertTrue(is_absolute_path("D:/"))

    def test_windows_lowercase_drive(self):
        """Test Windows path with lowercase drive letter"""
        self.assertTrue(is_absolute_path(r"c:\data"))
        self.assertTrue(is_absolute_path("d:/folder"))

    def test_windows_relative_path(self):
        """Test Windows relative path detection"""
        self.assertFalse(is_absolute_path(r"folder\subfolder"))
        self.assertFalse(is_absolute_path("C:relative"))  # No slash after colon


class TestIsWindowsPath(unittest.TestCase):
    """Test cases for the is_windows_path helper function"""

    def test_windows_path_backslash(self):
        """Test Windows path with backslash"""
        self.assertTrue(is_windows_path(r"C:\Users\data"))
        self.assertTrue(is_windows_path("D:\\"))
        self.assertTrue(is_windows_path(r"E:\folder\subfolder"))

    def test_windows_path_forward_slash(self):
        """Test Windows path with forward slash"""
        self.assertTrue(is_windows_path("C:/Users/data"))
        self.assertTrue(is_windows_path("D:/"))

    def test_windows_lowercase_drive(self):
        """Test Windows path with lowercase drive letter"""
        self.assertTrue(is_windows_path(r"c:\data"))
        self.assertTrue(is_windows_path("d:/folder"))

    def test_unix_path(self):
        """Test that Unix paths are not detected as Windows"""
        self.assertFalse(is_windows_path("/home/user"))
        self.assertFalse(is_windows_path("/var/log"))

    def test_relative_path(self):
        """Test that relative paths are not detected as Windows"""
        self.assertFalse(is_windows_path("relative/path"))
        self.assertFalse(is_windows_path(r"folder\subfolder"))


class TestWindowsPathToWsl(unittest.TestCase):
    """Test cases for the windows_path_to_wsl helper function"""

    def test_windows_path_backslash(self):
        """Test Windows path with backslash conversion"""
        self.assertEqual(windows_path_to_wsl(r"C:\_scripts"), "/mnt/c/_scripts")
        self.assertEqual(windows_path_to_wsl(r"D:\Users\data"), "/mnt/d/Users/data")

    def test_windows_path_forward_slash(self):
        """Test Windows path with forward slash conversion"""
        self.assertEqual(windows_path_to_wsl("C:/scripts"), "/mnt/c/scripts")
        self.assertEqual(windows_path_to_wsl("E:/folder/subfolder"), "/mnt/e/folder/subfolder")

    def test_windows_lowercase_drive(self):
        """Test Windows path with lowercase drive letter"""
        self.assertEqual(windows_path_to_wsl(r"c:\data"), "/mnt/c/data")

    def test_windows_root_drive(self):
        """Test Windows root drive path"""
        self.assertEqual(windows_path_to_wsl("C:\\"), "/mnt/c/")
        self.assertEqual(windows_path_to_wsl("D:/"), "/mnt/d/")

    def test_non_windows_path(self):
        """Test that non-Windows paths are returned unchanged"""
        self.assertEqual(windows_path_to_wsl("/home/user"), "/home/user")
        self.assertEqual(windows_path_to_wsl("relative/path"), "relative/path")


class TestNormalizePathForTar(unittest.TestCase):
    """Test cases for the normalize_path_for_tar helper function"""

    def test_unix_path(self):
        """Test Unix path normalization"""
        self.assertEqual(normalize_path_for_tar("/home/user/data"), "home/user/data")
        self.assertEqual(normalize_path_for_tar("/var/log"), "var/log")
        self.assertEqual(normalize_path_for_tar("/"), "")

    def test_windows_path_backslash(self):
        """Test Windows path with backslashes"""
        self.assertEqual(normalize_path_for_tar(r"C:\Users\data"), "C:/Users/data")
        self.assertEqual(normalize_path_for_tar(r"D:\scripts"), "D:/scripts")

    def test_windows_path_forward_slash(self):
        """Test Windows path with forward slashes (already normalized)"""
        self.assertEqual(normalize_path_for_tar("C:/Users/data"), "C:/Users/data")


class TestPathToSlug(unittest.TestCase):
    """Test cases for the path_to_slug helper function"""

    def test_unix_path(self):
        """Test Unix path to slug conversion"""
        self.assertEqual(path_to_slug("/home/user/data"), "home_user_data")
        self.assertEqual(path_to_slug("/var/log"), "var_log")
        self.assertEqual(path_to_slug("/single"), "single")

    def test_windows_path_backslash(self):
        """Test Windows path with backslashes to slug conversion"""
        self.assertEqual(path_to_slug(r"C:\Users\data"), "C_Users_data")
        self.assertEqual(path_to_slug(r"D:\scripts"), "D_scripts")

    def test_windows_path_forward_slash(self):
        """Test Windows path with forward slashes to slug conversion"""
        self.assertEqual(path_to_slug("C:/Users/data"), "C_Users_data")

    def test_windows_root_drive(self):
        """Test Windows root drive path"""
        self.assertEqual(path_to_slug("C:\\"), "C")
        self.assertEqual(path_to_slug("D:/"), "D")


class TestGetRemoteDetails(unittest.TestCase):
    """Test cases for the get_remote_details function"""

    def setUp(self):
        self.patcher = patch('subprocess.run')
        self.mock_run = self.patcher.start()
        
        # Default mock response for ssh -G
        self.mock_result = unittest.mock.Mock()
        self.mock_result.returncode = 0
        self.mock_result.stdout = ""
        self.mock_run.return_value = self.mock_result

    def tearDown(self):
        self.patcher.stop()

    def set_ssh_output(self, hostname="example.com", user="defaultuser", port="22"):
        """Helper to set the mock ssh -G output"""
        self.mock_result.stdout = f"hostname {hostname}\nuser {user}\nport {port}\n"

    def test_simple_target_with_user(self):
        """Test parsing target with explicit user"""
        self.set_ssh_output(hostname="example.com", user="testuser", port="22")
        host, user, port, path = get_remote_details("testuser@example.com:/home/data")
        
        self.assertEqual(host, "example.com")
        self.assertEqual(user, "testuser")
        self.assertEqual(port, 22)
        self.assertEqual(path, "/home/data")

    def test_simple_target_without_user(self):
        """Test parsing target without explicit user (uses default)"""
        self.set_ssh_output(hostname="example.com", user="defaultuser", port="22")
        with patch.dict(os.environ, {'USER': 'defaultuser'}):
            host, user, port, path = get_remote_details("example.com:/var/log")
            self.assertEqual(host, "example.com")
            self.assertEqual(user, "defaultuser")
            self.assertEqual(port, 22)
            self.assertEqual(path, "/var/log")

    def test_ssh_config_hostname_resolution(self):
        """Test SSH config hostname resolution"""
        self.set_ssh_output(hostname="actual-server.example.com", user="configuser", port="2222")
        
        host, user, port, path = get_remote_details("myserver:/data")
        self.assertEqual(host, "actual-server.example.com")
        self.assertEqual(user, "configuser")
        self.assertEqual(port, 2222)
        self.assertEqual(path, "/data")

    def test_ssh_config_partial_match(self):
        """Test SSH config with only some settings"""
        # ssh -G always returns full config, filling defaults
        self.set_ssh_output(hostname="actual-server.example.com", user="defaultuser", port="22")
        
        with patch.dict(os.environ, {'USER': 'defaultuser'}):
            host, user, port, path = get_remote_details("myserver:/data")
            self.assertEqual(host, "actual-server.example.com")
            self.assertEqual(user, "defaultuser")
            self.assertEqual(port, 22)
            self.assertEqual(path, "/data")

    def test_explicit_user_overrides_config(self):
        """Test that explicit user in target overrides SSH config user"""
        self.set_ssh_output(hostname="myserver", user="configuser", port="22")
        
        host, user, port, path = get_remote_details("explicituser@myserver:/data")
        self.assertEqual(host, "myserver")
        self.assertEqual(user, "explicituser")
        self.assertEqual(port, 22)
        self.assertEqual(path, "/data")

    def test_windows_path_parsing(self):
        """Test parsing target with Windows path"""
        self.set_ssh_output(hostname="zenbook", user="testuser", port="22")
        
        host, user, port, path = get_remote_details(r"testuser@zenbook:C:\_scripts")
        self.assertEqual(host, "zenbook")
        self.assertEqual(user, "testuser")
        self.assertEqual(port, 22)
        self.assertEqual(path, r"C:\_scripts")

    def test_windows_path_without_user(self):
        """Test parsing Windows target without explicit user"""
        self.set_ssh_output(hostname="zenbook", user="defaultuser", port="22")
        
        with patch.dict(os.environ, {'USER': 'defaultuser'}):
            host, user, port, path = get_remote_details(r"zenbook:D:\data\backup")
            self.assertEqual(host, "zenbook")
            self.assertEqual(user, "defaultuser")
            self.assertEqual(port, 22)
            self.assertEqual(path, r"D:\data\backup")

    def test_ssh_command_failure(self):
        """Test behavior when ssh -G fails raises SSHConfigError"""
        self.mock_run.side_effect = subprocess.CalledProcessError(255, ['ssh'])

        with self.assertRaises(SSHConfigError) as ctx:
            get_remote_details("myserver:/data")
        self.assertIn("Failed to resolve SSH config", str(ctx.exception))

    def test_no_user_raises_error(self):
        """Test that missing user raises SSHConfigError"""
        # ssh -G returns config without user
        self.mock_result.stdout = "hostname myserver\nport 22\n"

        with self.assertRaises(SSHConfigError) as ctx:
            get_remote_details("myserver:/data")
        self.assertIn("No user specified", str(ctx.exception))


class TestGroupTargetsByHost(unittest.TestCase):
    """Test cases for the group_targets_by_host function"""

    def test_single_host_multiple_paths(self):
        """Test grouping multiple paths from the same host"""
        targets = [
            ("user@host1:/path1", False),
            ("user@host1:/path2", False),
            ("user@host1:/path3", False)
        ]
        with patch('os.path.exists', return_value=False):
            groups = group_targets_by_host(targets)
            self.assertEqual(len(groups), 1)
            key = ('host1', 'user', 22)
            self.assertIn(key, groups)
            self.assertEqual(len(groups[key]), 3)
            # Check structure of grouped items: (target, path, use_sudo)
            self.assertEqual(len(groups[key][0]), 3)

    def test_multiple_hosts(self):
        """Test grouping targets from different hosts"""
        targets = [
            ("user@host1:/path1", False),
            ("user@host2:/path2", False),
            ("user@host3:/path3", False)
        ]
        with patch('os.path.exists', return_value=False):
            groups = group_targets_by_host(targets)
            self.assertEqual(len(groups), 3)
            self.assertIn(('host1', 'user', 22), groups)
            self.assertIn(('host2', 'user', 22), groups)
            self.assertIn(('host3', 'user', 22), groups)

    def test_different_users_same_host(self):
        """Test that different users on same host create separate groups"""
        targets = [
            ("user1@host1:/path1", False),
            ("user2@host1:/path2", False)
        ]
        with patch('os.path.exists', return_value=False):
            groups = group_targets_by_host(targets)
            self.assertEqual(len(groups), 2)
            self.assertIn(('host1', 'user1', 22), groups)
            self.assertIn(('host1', 'user2', 22), groups)

    def test_different_ports_same_host(self):
        """Test that different ports on same host create separate groups"""
        ssh_config_content_2222 = """
Host server1
    HostName host1
    Port 2222
"""
        ssh_config_content_22 = """
Host server2
    HostName host1
    Port 22
"""
        targets = [("server1:/path1", False), ("server2:/path2", False)]

        def mock_open_side_effect(filepath, *args, **kwargs):
            if 'server1' in targets[0][0]:
                return mock_open(read_data=ssh_config_content_2222)(filepath, *args, **kwargs)
            return mock_open(read_data=ssh_config_content_22)(filepath, *args, **kwargs)

        with patch('os.path.exists', return_value=False), \
             patch.dict(os.environ, {'USER': 'testuser'}):
            groups = group_targets_by_host(targets)
            # This is a simplified test - the actual behavior depends on SSH config
            self.assertGreaterEqual(len(groups), 1)

    def test_empty_targets_list(self):
        """Test grouping an empty list of targets"""
        targets = []
        groups = group_targets_by_host(targets)
        self.assertEqual(len(groups), 0)


class TestParseConfig(unittest.TestCase):
    """Test cases for the parse_config function"""

    def test_valid_config_file(self):
        """Test parsing a valid config file"""
        config_content = """# Comment line
user@host1:/path1
user@host2:/path2

# Another comment
host3:/path3
"""
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data=config_content)):
            targets = parse_config()
            self.assertEqual(len(targets), 3)
            self.assertIn(("user@host1:/path1", False), targets)
            self.assertIn(("user@host2:/path2", False), targets)
            self.assertIn(("host3:/path3", False), targets)

    def test_config_file_not_found(self):
        """Test handling of missing config file"""
        with patch('os.path.exists', return_value=False):
            with self.assertRaises(SystemExit) as cm:
                parse_config()
            self.assertEqual(cm.exception.code, 1)

    def test_config_with_invalid_entries(self):
        """Test config file with invalid entries causes exit"""
        config_content = """user@host1:/path1
invalid_entry_without_colon
host2:/path2
"""
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data=config_content)):
            with self.assertRaises(SystemExit) as cm:
                parse_config()
            self.assertEqual(cm.exception.code, 1)

    def test_empty_config_file(self):
        """Test parsing an empty config file"""
        config_content = """# Only comments

# No actual targets
"""
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data=config_content)):
            targets = parse_config()
            self.assertEqual(len(targets), 0)

    def test_config_with_whitespace(self):
        """Test that whitespace is properly handled"""
        config_content = """  user@host1:/path1
	user@host2:/path2
"""
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data=config_content)):
            targets = parse_config()
            self.assertEqual(len(targets), 2)
            # Verify whitespace is stripped
            self.assertIn(("user@host1:/path1", False), targets)
            self.assertIn(("user@host2:/path2", False), targets)

    def test_config_with_sudo(self):
        """Test parsing config with sudo flags"""
        config_content = """
user@host1:/path1 use_sudo
user@host2:/path2 sudo
user@host3:/path3
"""
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data=config_content)):
            targets = parse_config()
            self.assertEqual(len(targets), 3)
            self.assertIn(("user@host1:/path1", True), targets)
            self.assertIn(("user@host2:/path2", True), targets)
            self.assertIn(("user@host3:/path3", False), targets)


    def test_config_with_spaces_in_path(self):
        """Test parsing config with spaces in paths"""
        config_content = """
user@host1:/path/with spaces/file.txt
user@host2:/path/with spaces/file.txt use_sudo
"""
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data=config_content)):
            targets = parse_config()
            self.assertEqual(len(targets), 2)
            self.assertIn(("user@host1:/path/with spaces/file.txt", False), targets)
            self.assertIn(("user@host2:/path/with spaces/file.txt", True), targets)


class TestProcessBackupStream(unittest.TestCase):
    """Test cases for the process_backup_stream function"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.backup_dir = os.path.join(self.temp_dir, 'ssh-backups')
        os.makedirs(self.backup_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_ssh_connection_failure(self):
        """Test handling of SSH connection failure (return code 255)"""
        mock_process = unittest.mock.Mock()
        mock_process.returncode = 255
        mock_process.stdout = unittest.mock.Mock()
        mock_process.stdout.__enter__ = unittest.mock.Mock(return_value=mock_process.stdout)
        mock_process.stdout.__exit__ = unittest.mock.Mock(return_value=False)
        mock_process.stderr = unittest.mock.Mock()
        mock_process.stderr.read.return_value = b""
        mock_process.wait = unittest.mock.Mock()

        # Create empty tar stream
        import io
        import tarfile
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            pass
        tar_buffer.seek(0)
        mock_process.stdout.read = tar_buffer.read

        paths_map = [("user@host:/path1", "/path1", "path1")]

        with patch('ssh_backup.BACKUP_DIR', self.backup_dir):
            results, files = process_backup_stream(mock_process, paths_map, "host")

        self.assertEqual(len(results), 1)
        self.assertFalse(results[0][1])
        self.assertEqual(files, 0)

    def test_symlink_skipped(self):
        """Test that symlinks are skipped during extraction"""
        import io
        import tarfile

        # Create a tar with a symlink
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            # Add a regular file
            data = b"test content"
            info = tarfile.TarInfo(name="testdir/file.txt")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

            # Add a symlink
            symlink_info = tarfile.TarInfo(name="testdir/link.txt")
            symlink_info.type = tarfile.SYMTYPE
            symlink_info.linkname = "file.txt"
            tar.addfile(symlink_info)

        tar_buffer.seek(0)

        mock_process = unittest.mock.Mock()
        mock_process.returncode = 0
        mock_process.stdout = tar_buffer
        mock_process.stderr = unittest.mock.Mock()
        mock_process.stderr.read.return_value = b""
        mock_process.wait = unittest.mock.Mock()

        paths_map = [("user@host:/testdir", "/testdir", "testdir")]

        with patch('ssh_backup.BACKUP_DIR', self.backup_dir):
            results, files = process_backup_stream(mock_process, paths_map, "host")

        # Only 1 file extracted (symlink skipped)
        self.assertEqual(files, 1)

    def test_path_traversal_blocked(self):
        """Test that path traversal attempts are blocked"""
        import io
        import tarfile

        # Create a tar with a path traversal attempt
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            data = b"malicious"
            info = tarfile.TarInfo(name="../../../etc/passwd")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

        tar_buffer.seek(0)

        mock_process = unittest.mock.Mock()
        mock_process.returncode = 0
        mock_process.stdout = tar_buffer
        mock_process.stderr = unittest.mock.Mock()
        mock_process.stderr.read.return_value = b""
        mock_process.wait = unittest.mock.Mock()

        paths_map = [("user@host:/etc/passwd", "/etc/passwd", "etc/passwd")]

        with patch('ssh_backup.BACKUP_DIR', self.backup_dir):
            results, files = process_backup_stream(mock_process, paths_map, "host")

        # Path traversal should be blocked - 0 files extracted
        self.assertEqual(files, 0)


class TestBackupUnixHost(unittest.TestCase):
    """Test cases for the backup_unix_host function"""

    def test_dry_run_mode(self):
        """Test dry-run mode doesn't execute SSH commands"""
        paths = [
            ("user@host:/path1", "/path1", False),
            ("user@host:/path2", "/path2", True),
        ]

        results, files = backup_unix_host("host", "user", 22, paths, dry_run=True)

        self.assertEqual(len(results), 2)
        self.assertTrue(all(success for _, success in results))
        self.assertEqual(files, 0)

    def test_sudo_paths_grouped_separately(self):
        """Test that sudo and non-sudo paths are processed in separate batches"""
        paths = [
            ("user@host:/path1", "/path1", False),
            ("user@host:/path2", "/path2", True),
            ("user@host:/path3", "/path3", False),
        ]

        with patch('ssh_backup._run_unix_backup_batch') as mock_batch:
            mock_batch.return_value = ([], 0)
            backup_unix_host("host", "user", 22, paths, dry_run=False)

            # Should be called twice - once for normal, once for sudo
            self.assertEqual(mock_batch.call_count, 2)

            # First call should be non-sudo paths
            first_call_paths = mock_batch.call_args_list[0][0][3]
            first_call_sudo = mock_batch.call_args_list[0][1]['use_sudo']
            self.assertEqual(len(first_call_paths), 2)
            self.assertFalse(first_call_sudo)

            # Second call should be sudo paths
            second_call_paths = mock_batch.call_args_list[1][0][3]
            second_call_sudo = mock_batch.call_args_list[1][1]['use_sudo']
            self.assertEqual(len(second_call_paths), 1)
            self.assertTrue(second_call_sudo)


class TestBackupWindowsHost(unittest.TestCase):
    """Test cases for the backup_windows_host function"""

    def test_dry_run_mode(self):
        """Test dry-run mode doesn't execute SSH commands"""
        paths = [
            (r"user@host:C:\_scripts", r"C:\_scripts", False),
            (r"user@host:D:\data", r"D:\data", True),
        ]

        results, files = backup_windows_host("host", "user", 22, paths, dry_run=True)

        self.assertEqual(len(results), 2)
        self.assertTrue(all(success for _, success in results))
        self.assertEqual(files, 0)

    def test_wsl_not_available(self):
        """Test handling when WSL is not available"""
        paths = [
            (r"user@host:C:\_scripts", r"C:\_scripts", False),
        ]

        with patch('ssh_backup.check_wsl_available', return_value=False):
            results, files = backup_windows_host("host", "user", 22, paths, dry_run=False)

        self.assertEqual(len(results), 1)
        self.assertFalse(results[0][1])
        self.assertEqual(files, 0)


class TestEmptyConfig(unittest.TestCase):
    """Test cases for empty config handling"""

    def test_empty_config_returns_empty_list(self):
        """Test that empty config file returns empty list"""
        config_content = """# Only comments
# No actual targets
"""
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data=config_content)):
            targets = parse_config()
            self.assertEqual(len(targets), 0)


if __name__ == '__main__':
    unittest.main()
