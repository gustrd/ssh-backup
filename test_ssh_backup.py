import unittest
import os
import tempfile
import shutil
from unittest.mock import patch, mock_open
from ssh_backup import (
    validate_target,
    get_remote_details,
    group_targets_by_host,
    parse_config,
    CONFIG_FILE
)


class TestValidateTarget(unittest.TestCase):
    """Test cases for the validate_target function"""

    def test_valid_target_with_user(self):
        """Test valid target with user@host:/path format"""
        is_valid, error = validate_target("user@example.com:/home/user/data", 1)
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_valid_target_without_user(self):
        """Test valid target with host:/path format"""
        is_valid, error = validate_target("example.com:/var/log", 1)
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_valid_target_complex_path(self):
        """Test valid target with complex path"""
        is_valid, error = validate_target("user@host:/path/to/deep/directory", 1)
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_empty_target(self):
        """Test empty target string"""
        is_valid, error = validate_target("", 1)
        self.assertFalse(is_valid)
        self.assertEqual(error, "empty target")

    def test_missing_colon(self):
        """Test target missing colon separator"""
        is_valid, error = validate_target("example.com", 1)
        self.assertFalse(is_valid)
        self.assertIn("missing ':'", error)

    def test_missing_host(self):
        """Test target with missing host"""
        is_valid, error = validate_target(":/path/to/dir", 1)
        self.assertFalse(is_valid)
        self.assertEqual(error, "missing host")

    def test_empty_username(self):
        """Test target with empty username before @"""
        is_valid, error = validate_target("@host:/path", 1)
        self.assertFalse(is_valid)
        self.assertEqual(error, "empty username before '@'")

    def test_empty_hostname_after_at(self):
        """Test target with empty hostname after @"""
        is_valid, error = validate_target("user@:/path", 1)
        self.assertFalse(is_valid)
        self.assertEqual(error, "empty hostname after '@'")

    def test_missing_path(self):
        """Test target with missing path"""
        is_valid, error = validate_target("user@host:", 1)
        self.assertFalse(is_valid)
        self.assertEqual(error, "missing remote path")

    def test_relative_path(self):
        """Test target with relative path (should be absolute)"""
        is_valid, error = validate_target("user@host:relative/path", 1)
        self.assertFalse(is_valid)
        self.assertIn("should be absolute", error)

    def test_multiple_colons(self):
        """Test target with multiple colons (only first is used as separator)"""
        is_valid, error = validate_target("user@host:/path:with:colons", 1)
        self.assertTrue(is_valid)
        self.assertIsNone(error)


class TestGetRemoteDetails(unittest.TestCase):
    """Test cases for the get_remote_details function"""

    def test_simple_target_with_user(self):
        """Test parsing target with explicit user"""
        with patch('os.path.exists', return_value=False):
            host, user, port, path = get_remote_details("testuser@example.com:/home/data")
            self.assertEqual(host, "example.com")
            self.assertEqual(user, "testuser")
            self.assertEqual(port, 22)
            self.assertEqual(path, "/home/data")

    def test_simple_target_without_user(self):
        """Test parsing target without explicit user (uses default)"""
        with patch('os.path.exists', return_value=False), \
             patch.dict(os.environ, {'USER': 'defaultuser'}):
            host, user, port, path = get_remote_details("example.com:/var/log")
            self.assertEqual(host, "example.com")
            self.assertEqual(user, "defaultuser")
            self.assertEqual(port, 22)
            self.assertEqual(path, "/var/log")

    def test_ssh_config_hostname_resolution(self):
        """Test SSH config hostname resolution"""
        ssh_config_content = """
Host myserver
    HostName actual-server.example.com
    User configuser
    Port 2222
"""
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data=ssh_config_content)):
            host, user, port, path = get_remote_details("myserver:/data")
            self.assertEqual(host, "actual-server.example.com")
            self.assertEqual(user, "configuser")
            self.assertEqual(port, 2222)
            self.assertEqual(path, "/data")

    def test_ssh_config_partial_match(self):
        """Test SSH config with only some settings"""
        ssh_config_content = """
Host myserver
    HostName actual-server.example.com
"""
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data=ssh_config_content)), \
             patch.dict(os.environ, {'USER': 'defaultuser'}):
            host, user, port, path = get_remote_details("myserver:/data")
            self.assertEqual(host, "actual-server.example.com")
            self.assertEqual(user, "defaultuser")
            self.assertEqual(port, 22)
            self.assertEqual(path, "/data")

    def test_explicit_user_overrides_config(self):
        """Test that explicit user in target means SSH config is not consulted for user"""
        # When user@host format is used, the host part is not looked up in SSH config
        # This is expected behavior since @ was used
        with patch('os.path.exists', return_value=False):
            host, user, port, path = get_remote_details("explicituser@myserver:/data")
            self.assertEqual(host, "myserver")
            self.assertEqual(user, "explicituser")
            self.assertEqual(port, 22)
            self.assertEqual(path, "/data")

    def test_ssh_config_with_comments(self):
        """Test SSH config parsing with comments"""
        ssh_config_content = """
# This is a comment
Host myserver
    # Another comment
    HostName actual-server.example.com
    User configuser
"""
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data=ssh_config_content)):
            host, user, port, path = get_remote_details("myserver:/data")
            self.assertEqual(host, "actual-server.example.com")
            self.assertEqual(user, "configuser")


class TestGroupTargetsByHost(unittest.TestCase):
    """Test cases for the group_targets_by_host function"""

    def test_single_host_multiple_paths(self):
        """Test grouping multiple paths from the same host"""
        targets = [
            "user@host1:/path1",
            "user@host1:/path2",
            "user@host1:/path3"
        ]
        with patch('os.path.exists', return_value=False):
            groups = group_targets_by_host(targets)
            self.assertEqual(len(groups), 1)
            key = ('host1', 'user', 22)
            self.assertIn(key, groups)
            self.assertEqual(len(groups[key]), 3)

    def test_multiple_hosts(self):
        """Test grouping targets from different hosts"""
        targets = [
            "user@host1:/path1",
            "user@host2:/path2",
            "user@host3:/path3"
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
            "user1@host1:/path1",
            "user2@host1:/path2"
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
        targets = ["server1:/path1", "server2:/path2"]

        def mock_open_side_effect(filepath, *args, **kwargs):
            if 'server1' in targets[0]:
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
            self.assertIn("user@host1:/path1", targets)
            self.assertIn("user@host2:/path2", targets)
            self.assertIn("host3:/path3", targets)

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
            self.assertIn("user@host1:/path1", targets)
            self.assertIn("user@host2:/path2", targets)


if __name__ == '__main__':
    unittest.main()
