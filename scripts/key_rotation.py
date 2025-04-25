#!/usr/bin/env python3
"""
Key Rotation Script for Incept5 Cryptography Library

This script rotates encryption keys by:
1. Connecting to the database
2. Retrieving all encrypted values from the vault
3. Decrypting them using the old key
4. Encrypting them using the new key
5. Updating the vault with the newly encrypted values

Usage:
    python key_rotation.py --config <config_file_path> [--dry-run]

Example:
    python key_rotation.py --config key_rotation_config.yaml --dry-run
"""

import argparse
import base64
import json
import logging
import os
import sys
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import psycopg2
import yaml
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('key_rotation')

class EncryptionKey:
    """Represents an encryption key with AES and HMAC components"""
    
    def __init__(self, key_id: str, aes_key_base64: str, hmac_key_base64: str):
        self.key_id = key_id
        self.aes_key = base64.b64decode(aes_key_base64)
        self.hmac_key = base64.b64decode(hmac_key_base64)


class EncryptedValue:
    """Represents an encrypted value with all its components"""
    
    def __init__(self, provider: str, key_id: str, hmac_value: str, 
                 encrypted_value: str, initialization_vector: str):
        self.provider = provider
        self.key_id = key_id
        self.hmac = hmac_value
        self.encrypted_value = encrypted_value
        self.initialization_vector = initialization_vector
    
    @classmethod
    def from_string(cls, json_str: str) -> 'EncryptedValue':
        """Parse an encrypted value from its JSON string representation"""
        data = json.loads(json_str)
        return cls(
            provider=data.get('provider'),
            key_id=data.get('keyId'),
            hmac_value=data.get('hmac'),
            encrypted_value=data.get('encryptedValue'),
            initialization_vector=data.get('initialisationVector')
        )
    
    def as_string(self) -> str:
        """Convert the encrypted value to its JSON string representation"""
        data = {
            'provider': self.provider,
            'keyId': self.key_id,
            'hmac': self.hmac,
            'encryptedValue': self.encrypted_value,
            'initialisationVector': self.initialization_vector
        }
        return json.dumps(data)


class EncryptionService:
    """Service for encrypting and decrypting data"""
    
    PROVIDER_ID = "Incept5EncryptionProviderV1"
    ENC_ALGORITHM = "AES/CBC/PKCS5Padding"
    MAGIC_NULL_VALUE = "0e27b9e4-258a-40f2-8135-5cd44a3f56ef"
    
    def __init__(self, encryption_key: EncryptionKey, decryption_keys: List[EncryptionKey]):
        self.encryption_key = encryption_key
        self.decryption_keys = {key.key_id: key for key in decryption_keys}
    
    def encrypt(self, plain_bytes: Optional[bytes]) -> str:
        """Encrypt bytes and return the encrypted value as a JSON string"""
        if plain_bytes is None:
            plain_bytes = self.MAGIC_NULL_VALUE.encode('utf-8')
        
        # Generate a random IV
        iv = self._generate_iv()
        
        # Encrypt the data
        cipher = Cipher(
            algorithms.AES(self.encryption_key.aes_key),
            modes.CBC(iv)
        )
        encryptor = cipher.encryptor()
        
        # Add PKCS7 padding
        padded_data = self._add_pkcs7_padding(plain_bytes)
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Generate HMAC
        hmac_value = self._generate_hmac(ciphertext, iv, self.encryption_key.hmac_key)
        
        # Create the encrypted value
        encrypted_value = EncryptedValue(
            provider=self.PROVIDER_ID,
            key_id=self.encryption_key.key_id,
            hmac_value=base64.b64encode(hmac_value).decode('utf-8'),
            encrypted_value=base64.b64encode(ciphertext).decode('utf-8'),
            initialization_vector=base64.b64encode(iv).decode('utf-8')
        )
        
        return encrypted_value.as_string()
    
    def decrypt_as_bytes(self, encrypted_value_str: str) -> Optional[bytes]:
        """Decrypt an encrypted value string and return the original bytes"""
        if not encrypted_value_str:
            return None
        
        encrypted_value = EncryptedValue.from_string(encrypted_value_str)
        
        # Get the decryption key
        if encrypted_value.key_id not in self.decryption_keys:
            raise ValueError(f"No matching key found for decryption. The data is encrypted with key id: {encrypted_value.key_id}")
        
        decryption_key = self.decryption_keys[encrypted_value.key_id]
        
        # Decode the components
        ciphertext = base64.b64decode(encrypted_value.encrypted_value)
        iv = base64.b64decode(encrypted_value.initialization_vector)
        stored_hmac = base64.b64decode(encrypted_value.hmac)
        
        # Verify HMAC
        computed_hmac = self._generate_hmac(ciphertext, iv, decryption_key.hmac_key)
        if not self._constant_time_compare(computed_hmac, stored_hmac):
            raise ValueError("HMAC verification failed. Data may have been tampered with.")
        
        # Decrypt the data
        cipher = Cipher(
            algorithms.AES(decryption_key.aes_key),
            modes.CBC(iv)
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS7 padding
        plaintext = self._remove_pkcs7_padding(padded_plaintext)
        
        # Check for null magic value
        if plaintext == self.MAGIC_NULL_VALUE.encode('utf-8'):
            return None
        
        return plaintext
    
    def _generate_iv(self) -> bytes:
        """Generate a random initialization vector"""
        return os.urandom(16)
    
    def _generate_hmac(self, ciphertext: bytes, iv: bytes, hmac_key: bytes) -> bytes:
        """Generate an HMAC for the ciphertext and IV"""
        h = hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(ciphertext + iv)
        return h.finalize()
    
    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """Compare two byte strings in constant time to prevent timing attacks"""
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        
        return result == 0
    
    def _add_pkcs7_padding(self, data: bytes) -> bytes:
        """Add PKCS7 padding to the data"""
        block_size = 16  # AES block size
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length]) * padding_length
        return data + padding
    
    def _remove_pkcs7_padding(self, padded_data: bytes) -> bytes:
        """Remove PKCS7 padding from the data"""
        padding_length = padded_data[-1]
        if padding_length > 16:
            raise ValueError("Invalid padding")
        
        # Verify padding
        for i in range(1, padding_length + 1):
            if padded_data[-i] != padding_length:
                raise ValueError("Invalid padding")
        
        return padded_data[:-padding_length]


class VaultRotator:
    """Handles the rotation of encryption keys in the vault"""
    
    def __init__(self, db_connection, schema: str, old_encryption_service: EncryptionService, 
                 new_encryption_service: EncryptionService, dry_run: bool = False):
        self.conn = db_connection
        self.schema = schema
        self.table_name = f"{schema}.vault" if schema else "vault"
        self.old_encryption_service = old_encryption_service
        self.new_encryption_service = new_encryption_service
        self.dry_run = dry_run
    
    def rotate_keys(self) -> Tuple[int, int]:
        """
        Rotate encryption keys for all items in the vault
        
        Returns:
            Tuple[int, int]: (total_items, updated_items)
        """
        logger.info(f"Starting key rotation process for table {self.table_name}")
        
        # Get all items from the vault
        items = self._get_all_vault_items()
        total_items = len(items)
        logger.info(f"Found {total_items} items in the vault")
        
        if self.dry_run:
            logger.info("DRY RUN MODE: No changes will be made to the database")
        
        # Process each item
        updated_items = 0
        for item_id, encrypted_content in items:
            try:
                # Decrypt with old key
                decrypted_bytes = self.old_encryption_service.decrypt_as_bytes(encrypted_content)
                
                # Encrypt with new key
                new_encrypted_content = self.new_encryption_service.encrypt(decrypted_bytes)
                
                # Update the vault
                if not self.dry_run:
                    self._update_vault_item(item_id, new_encrypted_content)
                
                updated_items += 1
                if updated_items % 100 == 0:
                    logger.info(f"Processed {updated_items}/{total_items} items")
                
            except Exception as e:
                logger.error(f"Error processing item {item_id}: {str(e)}")
        
        logger.info(f"Key rotation completed. Updated {updated_items}/{total_items} items.")
        return total_items, updated_items
    
    def _get_all_vault_items(self) -> List[Tuple[uuid.UUID, str]]:
        """Get all items from the vault"""
        with self.conn.cursor() as cursor:
            cursor.execute(f"SELECT id, encrypted_contents FROM {self.table_name}")
            return cursor.fetchall()
    
    def _update_vault_item(self, item_id: uuid.UUID, encrypted_content: str) -> None:
        """Update a vault item with new encrypted content"""
        with self.conn.cursor() as cursor:
            cursor.execute(
                f"UPDATE {self.table_name} SET encrypted_contents = %s WHERE id = %s",
                (encrypted_content, item_id)
            )
        self.conn.commit()


def load_config(config_file: str) -> Dict:
    """Load configuration from YAML file"""
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        
        # Validate required configuration
        required_sections = ['database', 'old_key', 'new_key']
        for section in required_sections:
            if section not in config:
                raise ValueError(f"Missing required configuration section: {section}")
        
        # Validate database configuration
        required_db_fields = ['url', 'username', 'password']
        for field in required_db_fields:
            if field not in config['database']:
                raise ValueError(f"Missing required database configuration field: {field}")
        
        # Validate key configurations
        for key_type in ['old_key', 'new_key']:
            required_key_fields = ['id', 'aes', 'hmac']
            for field in required_key_fields:
                if field not in config[key_type]:
                    raise ValueError(f"Missing required {key_type} configuration field: {field}")
        
        return config
    except Exception as e:
        logger.error(f"Error loading configuration: {str(e)}")
        raise


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Rotate encryption keys in the vault')
    
    # Configuration file
    parser.add_argument('--config', required=True, help='Path to the YAML configuration file')
    
    # Optional parameters
    parser.add_argument('--dry-run', action='store_true', help='Perform a dry run without making changes')
    
    return parser.parse_args()


def extract_db_info(jdbc_url: str) -> Tuple[str, str, str]:
    """Extract host, port, and database name from a JDBC URL"""
    # Example: jdbc:postgresql://localhost:5432/cryptography_test
    if not jdbc_url.startswith('jdbc:postgresql://'):
        raise ValueError("Only PostgreSQL JDBC URLs are supported")
    
    # Remove the jdbc:postgresql:// prefix
    url = jdbc_url[jdbc_url.find('//') + 2:]
    
    # Split into host:port and database
    host_port, database = url.split('/', 1)
    
    # Split host and port
    if ':' in host_port:
        host, port = host_port.split(':')
    else:
        host = host_port
        port = '5432'  # Default PostgreSQL port
    
    return host, port, database


def main():
    """Main function"""
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        # Load configuration
        config = load_config(args.config)
        
        # Extract database connection info
        host, port, database = extract_db_info(config['database']['url'])
        
        # Create encryption keys
        old_key = EncryptionKey(
            config['old_key']['id'],
            config['old_key']['aes'],
            config['old_key']['hmac']
        )
        
        new_key = EncryptionKey(
            config['new_key']['id'],
            config['new_key']['aes'],
            config['new_key']['hmac']
        )
        
        # Create encryption services
        old_encryption_service = EncryptionService(old_key, [old_key])
        new_encryption_service = EncryptionService(new_key, [new_key, old_key])
        
        # Get schema from config or use default
        schema = config.get('database', {}).get('schema', '')
        
        # Connect to the database
        logger.info(f"Connecting to database {database} on {host}:{port}")
        conn = psycopg2.connect(
            host=host,
            port=port,
            database=database,
            user=config['database']['username'],
            password=config['database']['password']
        )
        
        try:
            # Create and run the vault rotator
            rotator = VaultRotator(
                conn, 
                schema, 
                old_encryption_service, 
                new_encryption_service, 
                args.dry_run
            )
            
            total, updated = rotator.rotate_keys()
            
            if args.dry_run:
                logger.info("DRY RUN completed. No changes were made.")
            else:
                logger.info(f"Key rotation completed successfully. Updated {updated}/{total} items.")
            
            return 0
        finally:
            conn.close()
    
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return 1


if __name__ == '__main__':
    sys.exit(main())
