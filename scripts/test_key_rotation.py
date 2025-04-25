#!/usr/bin/env python3
"""
Unit tests for the key rotation script.

These tests verify the functionality of the key rotation script components
without requiring a real database connection.

Run with:
    python -m unittest scripts/test_key_rotation.py
"""

import base64
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import yaml

# Import the modules from key_rotation.py
from key_rotation import (
    EncryptedValue,
    EncryptionKey,
    EncryptionService,
    VaultRotator,
    extract_db_info,
    load_config
)


class TestEncryptionKey(unittest.TestCase):
    """Test the EncryptionKey class"""

    def test_encryption_key_initialization(self):
        """Test that EncryptionKey properly initializes with base64 keys"""
        # Arrange
        key_id = "test-key-id"
        aes_key_base64 = base64.b64encode(os.urandom(32)).decode('utf-8')
        hmac_key_base64 = base64.b64encode(os.urandom(32)).decode('utf-8')
        
        # Act
        key = EncryptionKey(key_id, aes_key_base64, hmac_key_base64)
        
        # Assert
        self.assertEqual(key.key_id, key_id)
        self.assertEqual(len(key.aes_key), 32)  # AES-256 key is 32 bytes
        self.assertEqual(len(key.hmac_key), 32)  # HMAC-SHA256 key is 32 bytes


class TestEncryptedValue(unittest.TestCase):
    """Test the EncryptedValue class"""

    def test_encrypted_value_serialization(self):
        """Test that EncryptedValue can be serialized to and from JSON"""
        # Arrange
        provider = "TestProvider"
        key_id = "test-key-id"
        hmac = "hmac-value"
        encrypted_value = "encrypted-data"
        iv = "initialization-vector"
        
        # Act
        value = EncryptedValue(provider, key_id, hmac, encrypted_value, iv)
        json_str = value.as_string()
        deserialized = EncryptedValue.from_string(json_str)
        
        # Assert
        self.assertEqual(deserialized.provider, provider)
        self.assertEqual(deserialized.key_id, key_id)
        self.assertEqual(deserialized.hmac, hmac)
        self.assertEqual(deserialized.encrypted_value, encrypted_value)
        self.assertEqual(deserialized.initialization_vector, iv)


class TestEncryptionService(unittest.TestCase):
    """Test the EncryptionService class"""

    def setUp(self):
        """Set up test keys for encryption/decryption"""
        self.key_id = "test-key-id"
        self.aes_key = base64.b64encode(os.urandom(32)).decode('utf-8')
        self.hmac_key = base64.b64encode(os.urandom(32)).decode('utf-8')
        self.encryption_key = EncryptionKey(self.key_id, self.aes_key, self.hmac_key)
        self.encryption_service = EncryptionService(self.encryption_key, [self.encryption_key])

    def test_encrypt_decrypt_cycle(self):
        """Test that data can be encrypted and then decrypted correctly"""
        # Arrange
        test_data = "This is a test string to encrypt and decrypt"
        test_bytes = test_data.encode('utf-8')
        
        # Act
        encrypted = self.encryption_service.encrypt(test_bytes)
        decrypted_bytes = self.encryption_service.decrypt_as_bytes(encrypted)
        decrypted = decrypted_bytes.decode('utf-8')
        
        # Assert
        self.assertNotEqual(encrypted, test_data)  # Encrypted data should be different
        self.assertEqual(decrypted, test_data)     # Decrypted data should match original

    def test_encrypt_decrypt_null(self):
        """Test that null values can be encrypted and decrypted correctly"""
        # Act
        encrypted = self.encryption_service.encrypt(None)
        decrypted = self.encryption_service.decrypt_as_bytes(encrypted)
        
        # Assert
        self.assertIsNone(decrypted)  # Should decrypt back to None

    def test_decrypt_with_wrong_key_fails(self):
        """Test that decryption fails with the wrong key"""
        # Arrange
        test_data = "This is a test string"
        encrypted = self.encryption_service.encrypt(test_data.encode('utf-8'))
        
        # Create a new key and service
        wrong_key_id = "wrong-key-id"
        wrong_aes_key = base64.b64encode(os.urandom(32)).decode('utf-8')
        wrong_hmac_key = base64.b64encode(os.urandom(32)).decode('utf-8')
        wrong_key = EncryptionKey(wrong_key_id, wrong_aes_key, wrong_hmac_key)
        wrong_service = EncryptionService(wrong_key, [wrong_key])
        
        # Act & Assert
        with self.assertRaises(ValueError):
            wrong_service.decrypt_as_bytes(encrypted)


class TestVaultRotator(unittest.TestCase):
    """Test the VaultRotator class"""

    def setUp(self):
        """Set up mock objects for testing"""
        # Create mock encryption services
        self.old_encryption_service = MagicMock()
        self.new_encryption_service = MagicMock()
        
        # Create mock database connection
        self.conn = MagicMock()
        self.cursor = MagicMock()
        self.conn.cursor.return_value.__enter__.return_value = self.cursor
        
        # Create the vault rotator
        self.schema = "test_schema"
        self.rotator = VaultRotator(
            self.conn,
            self.schema,
            self.old_encryption_service,
            self.new_encryption_service,
            dry_run=False
        )

    def test_rotate_keys(self):
        """Test that keys are rotated correctly"""
        # Arrange
        # Mock data for the vault items
        item_id1 = "11111111-1111-1111-1111-111111111111"
        item_id2 = "22222222-2222-2222-2222-222222222222"
        encrypted_content1 = '{"provider":"TestProvider","keyId":"old-key","hmac":"hmac1","encryptedValue":"enc1","initialisationVector":"iv1"}'
        encrypted_content2 = '{"provider":"TestProvider","keyId":"old-key","hmac":"hmac2","encryptedValue":"enc2","initialisationVector":"iv2"}'
        
        # Mock the database query results
        self.cursor.fetchall.return_value = [
            (item_id1, encrypted_content1),
            (item_id2, encrypted_content2)
        ]
        
        # Mock the decryption/encryption process
        decrypted1 = b"decrypted content 1"
        decrypted2 = b"decrypted content 2"
        new_encrypted1 = '{"provider":"TestProvider","keyId":"new-key","hmac":"new-hmac1","encryptedValue":"new-enc1","initialisationVector":"new-iv1"}'
        new_encrypted2 = '{"provider":"TestProvider","keyId":"new-key","hmac":"new-hmac2","encryptedValue":"new-enc2","initialisationVector":"new-iv2"}'
        
        self.old_encryption_service.decrypt_as_bytes.side_effect = [decrypted1, decrypted2]
        self.new_encryption_service.encrypt.side_effect = [new_encrypted1, new_encrypted2]
        
        # Act
        total, updated = self.rotator.rotate_keys()
        
        # Assert
        self.assertEqual(total, 2)
        self.assertEqual(updated, 2)
        self.cursor.execute.assert_any_call(f"SELECT id, encrypted_contents FROM {self.schema}.vault")
        
        # Check that each item was updated with the new encrypted content
        update_calls = [
            call for call in self.cursor.execute.call_args_list 
            if call[0][0].startswith(f"UPDATE {self.schema}.vault")
        ]
        self.assertEqual(len(update_calls), 2)
        
        # Verify the old encryption service was used to decrypt
        self.old_encryption_service.decrypt_as_bytes.assert_any_call(encrypted_content1)
        self.old_encryption_service.decrypt_as_bytes.assert_any_call(encrypted_content2)
        
        # Verify the new encryption service was used to encrypt
        self.new_encryption_service.encrypt.assert_any_call(decrypted1)
        self.new_encryption_service.encrypt.assert_any_call(decrypted2)

    def test_dry_run_mode(self):
        """Test that dry run mode doesn't update the database"""
        # Arrange
        # Create a rotator in dry run mode
        dry_run_rotator = VaultRotator(
            self.conn,
            self.schema,
            self.old_encryption_service,
            self.new_encryption_service,
            dry_run=True
        )
        
        # Mock data for the vault items
        item_id = "11111111-1111-1111-1111-111111111111"
        encrypted_content = '{"provider":"TestProvider","keyId":"old-key","hmac":"hmac","encryptedValue":"enc","initialisationVector":"iv"}'
        
        # Mock the database query results
        self.cursor.fetchall.return_value = [(item_id, encrypted_content)]
        
        # Mock the decryption/encryption process
        decrypted = b"decrypted content"
        new_encrypted = '{"provider":"TestProvider","keyId":"new-key","hmac":"new-hmac","encryptedValue":"new-enc","initialisationVector":"new-iv"}'
        
        self.old_encryption_service.decrypt_as_bytes.return_value = decrypted
        self.new_encryption_service.encrypt.return_value = new_encrypted
        
        # Act
        total, updated = dry_run_rotator.rotate_keys()
        
        # Assert
        self.assertEqual(total, 1)
        self.assertEqual(updated, 1)
        
        # Verify SELECT was called but UPDATE was not
        self.cursor.execute.assert_called_once_with(f"SELECT id, encrypted_contents FROM {self.schema}.vault")
        
        # Verify the encryption services were called
        self.old_encryption_service.decrypt_as_bytes.assert_called_once_with(encrypted_content)
        self.new_encryption_service.encrypt.assert_called_once_with(decrypted)
        
        # Verify commit was not called
        self.conn.commit.assert_not_called()


class TestConfigFunctions(unittest.TestCase):
    """Test the configuration-related functions"""

    def test_extract_db_info(self):
        """Test that database connection info is extracted correctly from JDBC URL"""
        # Test with standard URL including port
        host, port, database = extract_db_info("jdbc:postgresql://localhost:5432/testdb")
        self.assertEqual(host, "localhost")
        self.assertEqual(port, "5432")
        self.assertEqual(database, "testdb")
        
        # Test with URL without port (should default to 5432)
        host, port, database = extract_db_info("jdbc:postgresql://dbserver/mydb")
        self.assertEqual(host, "dbserver")
        self.assertEqual(port, "5432")
        self.assertEqual(database, "mydb")
        
        # Test with invalid URL format
        with self.assertRaises(ValueError):
            extract_db_info("invalid-url")

    def test_load_config(self):
        """Test that configuration is loaded correctly from YAML file"""
        # Create a temporary config file
        config_data = {
            "database": {
                "url": "jdbc:postgresql://localhost:5432/testdb",
                "username": "testuser",
                "password": "testpass",
                "schema": "testschema"
            },
            "old_key": {
                "id": "old-key-id",
                "aes": "old-aes-key",
                "hmac": "old-hmac-key"
            },
            "new_key": {
                "id": "new-key-id",
                "aes": "new-aes-key",
                "hmac": "new-hmac-key"
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            yaml.dump(config_data, temp_file)
            temp_file_path = temp_file.name
        
        try:
            # Load the config
            loaded_config = load_config(temp_file_path)
            
            # Verify the loaded config matches the original
            self.assertEqual(loaded_config["database"]["url"], config_data["database"]["url"])
            self.assertEqual(loaded_config["database"]["username"], config_data["database"]["username"])
            self.assertEqual(loaded_config["database"]["password"], config_data["database"]["password"])
            self.assertEqual(loaded_config["database"]["schema"], config_data["database"]["schema"])
            
            self.assertEqual(loaded_config["old_key"]["id"], config_data["old_key"]["id"])
            self.assertEqual(loaded_config["old_key"]["aes"], config_data["old_key"]["aes"])
            self.assertEqual(loaded_config["old_key"]["hmac"], config_data["old_key"]["hmac"])
            
            self.assertEqual(loaded_config["new_key"]["id"], config_data["new_key"]["id"])
            self.assertEqual(loaded_config["new_key"]["aes"], config_data["new_key"]["aes"])
            self.assertEqual(loaded_config["new_key"]["hmac"], config_data["new_key"]["hmac"])
        
        finally:
            # Clean up the temporary file
            os.unlink(temp_file_path)
    
    def test_load_config_missing_required_section(self):
        """Test that loading config fails when required sections are missing"""
        # Create a config missing the database section
        config_data = {
            "old_key": {
                "id": "old-key-id",
                "aes": "old-aes-key",
                "hmac": "old-hmac-key"
            },
            "new_key": {
                "id": "new-key-id",
                "aes": "new-aes-key",
                "hmac": "new-hmac-key"
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            yaml.dump(config_data, temp_file)
            temp_file_path = temp_file.name
        
        try:
            # Attempt to load the config
            with self.assertRaises(ValueError):
                load_config(temp_file_path)
        
        finally:
            # Clean up the temporary file
            os.unlink(temp_file_path)


if __name__ == '__main__':
    unittest.main()
