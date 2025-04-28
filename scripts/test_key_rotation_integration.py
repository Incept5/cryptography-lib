#!/usr/bin/env python3
"""
Integration tests for the key rotation script.

These tests verify the functionality of the key rotation script with a real database.
They require Docker to be installed and running to spin up a PostgreSQL container.

Run with:
    python -m unittest scripts/test_key_rotation_integration.py
"""

import base64
import json
import os
import subprocess
import tempfile
import time
import unittest
import uuid

import psycopg2
import psycopg2.extras
import yaml

# Import the modules from key_rotation.py
from key_rotation import (
    EncryptedValue,
    EncryptionKey,
    EncryptionService,
    VaultRotator
)


class TestKeyRotationIntegration(unittest.TestCase):
    """Integration tests for the key rotation script with a real database"""

    @classmethod
    def setUpClass(cls):
        """Set up a connection to PostgreSQL for testing"""
        # Define database connection parameters
        # These will work both locally and in CircleCI
        cls.db_name = os.environ.get("POSTGRES_DB", "cryptography_test")
        cls.db_user = os.environ.get("POSTGRES_USER", "postgres")
        cls.db_password = os.environ.get("POSTGRES_PASSWORD", "postgres")
        cls.db_host = os.environ.get("POSTGRES_HOST", "localhost")
        cls.db_port = os.environ.get("POSTGRES_PORT", "5432")

        psycopg2.extras.register_uuid()
        
        # Try to connect to the database, with retries
        max_retries = 5
        retry_delay = 2
        
        for attempt in range(max_retries):
            try:
                print(f"Attempting to connect to database (attempt {attempt+1}/{max_retries})...")
                cls.conn = psycopg2.connect(
                    host=cls.db_host,
                    port=cls.db_port,
                    database=cls.db_name,
                    user=cls.db_user,
                    password=cls.db_password
                )
                print("Successfully connected to the database")
                break
            except psycopg2.OperationalError as e:
                if attempt < max_retries - 1:
                    print(f"Failed to connect to database: {e}")
                    print(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    raise unittest.SkipTest(f"Could not connect to PostgreSQL: {e}")
        
        # Check if we have a valid connection
        if not hasattr(cls, 'conn') or cls.conn is None:
            raise unittest.SkipTest("Failed to establish database connection")
        
        # Create the vault table
        with cls.conn.cursor() as cursor:
            cursor.execute("""
                CREATE SCHEMA IF NOT EXISTS test_schema;
                CREATE TABLE IF NOT EXISTS test_schema.vault (
                    id UUID PRIMARY KEY,
                    encrypted_contents text NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
                );
            """)
        cls.conn.commit()
        
        # Create encryption keys
        cls.old_key_id = str(uuid.uuid4())
        cls.old_aes_key = base64.b64encode(os.urandom(32)).decode('utf-8')
        cls.old_hmac_key = base64.b64encode(os.urandom(32)).decode('utf-8')
        
        cls.new_key_id = str(uuid.uuid4())
        cls.new_aes_key = base64.b64encode(os.urandom(32)).decode('utf-8')
        cls.new_hmac_key = base64.b64encode(os.urandom(32)).decode('utf-8')
        
        # Create encryption services
        cls.old_key = EncryptionKey(cls.old_key_id, cls.old_aes_key, cls.old_hmac_key)
        cls.new_key = EncryptionKey(cls.new_key_id, cls.new_aes_key, cls.new_hmac_key)
        
        cls.old_encryption_service = EncryptionService(cls.old_key, [cls.old_key])
        cls.new_encryption_service = EncryptionService(cls.new_key, [cls.new_key, cls.old_key])

    @classmethod
    def tearDownClass(cls):
        """Clean up database connection"""
        if hasattr(cls, 'conn') and cls.conn:
            cls.conn.close()

    def setUp(self):
        """Set up test data for each test"""
        # Clear the vault table
        with self.conn.cursor() as cursor:
            cursor.execute("DELETE FROM test_schema.vault")
        self.conn.commit()
        
        # Insert test data
        self.test_data = [
            "Test data 1",
            "Test data 2 with special characters: !@#$%^&*()",
            "Test data 3 with unicode: 你好, こんにちは, 안녕하세요",
            None  # Test null value
        ]
        
        self.item_ids = []
        
        for data in self.test_data:
            item_id = uuid.uuid4()
            self.item_ids.append(item_id)
            
            if data is not None:
                encrypted = self.old_encryption_service.encrypt(data.encode('utf-8'))
            else:
                encrypted = self.old_encryption_service.encrypt(None)
            
            with self.conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO test_schema.vault (id, encrypted_contents) VALUES (%s, %s)",
                    (item_id, encrypted)
                )
        
        self.conn.commit()

    def test_key_rotation(self):
        """Test that keys are rotated correctly in the database"""
        # Create the vault rotator
        rotator = VaultRotator(
            self.conn,
            "test_schema",
            self.old_encryption_service,
            self.new_encryption_service,
            dry_run=False
        )
        
        # Rotate the keys
        total, updated = rotator.rotate_keys()
        
        # Verify the results
        self.assertEqual(total, len(self.test_data))
        self.assertEqual(updated, len(self.test_data))
        
        # Verify that the data can be decrypted with the new key
        with self.conn.cursor() as cursor:
            for i, item_id in enumerate(self.item_ids):
                cursor.execute(
                    "SELECT encrypted_contents FROM test_schema.vault WHERE id = %s",
                    (item_id,)
                )
                row = cursor.fetchone()
                self.assertIsNotNone(row)
                
                encrypted_content = row[0]
                
                # Verify that the encrypted content uses the new key
                encrypted_value = EncryptedValue.from_string(encrypted_content)
                self.assertEqual(encrypted_value.key_id, self.new_key_id)
                
                # Decrypt with the new encryption service
                decrypted_bytes = self.new_encryption_service.decrypt_as_bytes(encrypted_content)
                
                # Compare with the original data
                original_data = self.test_data[i]
                if original_data is not None:
                    self.assertEqual(decrypted_bytes.decode('utf-8'), original_data)
                else:
                    self.assertIsNone(decrypted_bytes)
    
    def test_dry_run_mode(self):
        """Test that dry run mode doesn't modify the database"""
        # Create the vault rotator in dry run mode
        rotator = VaultRotator(
            self.conn,
            "test_schema",
            self.old_encryption_service,
            self.new_encryption_service,
            dry_run=True
        )
        
        # Rotate the keys in dry run mode
        total, updated = rotator.rotate_keys()
        
        # Verify the results
        self.assertEqual(total, len(self.test_data))
        self.assertEqual(updated, len(self.test_data))
        
        # Verify that the data is still encrypted with the old key
        with self.conn.cursor() as cursor:
            for i, item_id in enumerate(self.item_ids):
                cursor.execute(
                    "SELECT encrypted_contents FROM test_schema.vault WHERE id = %s",
                    (item_id,)
                )
                row = cursor.fetchone()
                self.assertIsNotNone(row)
                
                encrypted_content = row[0]
                
                # Verify that the encrypted content still uses the old key
                encrypted_value = EncryptedValue.from_string(encrypted_content)
                self.assertEqual(encrypted_value.key_id, self.old_key_id)
                
                # Decrypt with the old encryption service
                decrypted_bytes = self.old_encryption_service.decrypt_as_bytes(encrypted_content)
                
                # Compare with the original data
                original_data = self.test_data[i]
                if original_data is not None:
                    self.assertEqual(decrypted_bytes.decode('utf-8'), original_data)
                else:
                    self.assertIsNone(decrypted_bytes)


if __name__ == '__main__':
    unittest.main()
