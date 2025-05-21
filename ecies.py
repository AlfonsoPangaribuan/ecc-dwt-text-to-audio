"""
ECIES implementation using Elliptic Curve Cryptography with AES-GCM and MAC.
"""
import os
import time
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey, UnsupportedAlgorithm


def generate_keypair(curve: str = 'secp256r1') -> Tuple[bytes, bytes]:
    """
    Generate an ECC key pair.
    
    Args:
        curve: The elliptic curve to use (default: secp256r1)
        
    Returns:
        Tuple containing (private_key_pem, public_key_pem)
    """
    try:
        # Map curve name to cryptography curve object
        curve_map = {
            'secp256r1': ec.SECP256R1(),
            'secp384r1': ec.SECP384R1(),
            'secp521r1': ec.SECP521R1(),
            'secp256k1': ec.SECP256K1()
        }
        
        if curve not in curve_map:
            raise ValueError(f"Unsupported curve: {curve}. Supported curves: {', '.join(curve_map.keys())}")
            
        # Generate private key
        private_key = ec.generate_private_key(
            curve_map[curve],
            default_backend()
        )
        
        # Get public key
        public_key = private_key.public_key()
        
        # Serialize keys to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
        
    except Exception as e:
        raise RuntimeError(f"Key generation failed: {str(e)}")


def save_keys(private_key_pem: bytes, public_key_pem: bytes, 
              private_key_path: str, public_key_path: str) -> None:
    """
    Save key pair to files.
    
    Args:
        private_key_pem: Private key in PEM format
        public_key_pem: Public key in PEM format
        private_key_path: Path to save private key
        public_key_path: Path to save public key
    """
    try:
        with open(private_key_path, 'wb') as f:
            f.write(private_key_pem)
            
        with open(public_key_path, 'wb') as f:
            f.write(public_key_pem)
            
    except IOError as e:
        raise IOError(f"Failed to save keys: {str(e)}")


def load_private_key(private_key_path: str) -> ec.EllipticCurvePrivateKey:
    """
    Load private key from file.
    
    Args:
        private_key_path: Path to private key file
        
    Returns:
        EllipticCurvePrivateKey object
    """
    try:
        with open(private_key_path, 'rb') as f:
            private_key_data = f.read()
            
        try:
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=None,
                backend=default_backend()
            )
        except ValueError:
            # Try DER format if PEM fails
            try:
                private_key = serialization.load_der_private_key(
                    private_key_data,
                    password=None,
                    backend=default_backend()
                )
            except Exception:
                raise ValueError("Invalid key format. The key must be in PEM or DER format.")
                
        # Validate key type
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise TypeError("The loaded key is not an ECC private key.")
            
        return private_key
        
    except FileNotFoundError:
        raise FileNotFoundError(f"Private key file not found: {private_key_path}")
    except Exception as e:
        raise RuntimeError(f"Failed to load private key: {str(e)}")


def load_public_key(public_key_path: str) -> ec.EllipticCurvePublicKey:
    """
    Load public key from file.
    
    Args:
        public_key_path: Path to public key file
        
    Returns:
        EllipticCurvePublicKey object
    """
    try:
        with open(public_key_path, 'rb') as f:
            public_key_data = f.read()
            
        try:
            public_key = serialization.load_pem_public_key(
                public_key_data,
                backend=default_backend()
            )
        except ValueError:
            # Try DER format if PEM fails
            try:
                public_key = serialization.load_der_public_key(
                    public_key_data,
                    backend=default_backend()
                )
            except Exception:
                raise ValueError("Invalid key format. The key must be in PEM or DER format.")
                
        # Validate key type
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise TypeError("The loaded key is not an ECC public key.")
            
        return public_key
        
    except FileNotFoundError:
        raise FileNotFoundError(f"Public key file not found: {public_key_path}")
    except Exception as e:
        raise RuntimeError(f"Failed to load public key: {str(e)}")


def encrypt_ecies(public_key: ec.EllipticCurvePublicKey, plaintext: bytes) -> bytes:
    """
    Encrypt data using ECIES.
    
    Args:
        public_key: Recipient's public key
        plaintext: Data to encrypt
        
    Returns:
        Encrypted packet: R || nonce || ciphertext || tag
    """
    try:
        # Generate ephemeral key pair
        ephemeral_private_key = ec.generate_private_key(
            public_key.curve,
            default_backend()
        )
        ephemeral_public_key = ephemeral_private_key.public_key()
        
        # Compute shared secret: r·Kb
        shared_secret = ephemeral_private_key.exchange(
            ec.ECDH(),
            public_key
        )
        
        # Derive encryption and MAC keys using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=48,  # 32 bytes for AES-256 + 16 bytes for MAC
            salt=None,
            info=b'ECIES',
            backend=default_backend()
        ).derive(shared_secret)
        
        encryption_key = derived_key[:32]
        mac_key = derived_key[32:48]
        
        # Generate nonce for AES-GCM
        nonce = os.urandom(12)
        
        # Encrypt with AES-GCM (includes authentication tag)
        aesgcm = AESGCM(encryption_key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
        
        # Serialize ephemeral public key (R = r·G)
        R = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Return the complete packet: R || nonce || ciphertext || tag
        # Note: AES-GCM already includes the tag in the ciphertext
        return R + nonce + ciphertext_with_tag
        
    except Exception as e:
        raise RuntimeError(f"Encryption failed: {str(e)}")


def decrypt_ecies(private_key: ec.EllipticCurvePrivateKey, packet: bytes) -> bytes:
    """
    Decrypt data using ECIES.
    
    Args:
        private_key: Recipient's private key
        packet: Encrypted packet (R || nonce || ciphertext || tag)
        
    Returns:
        Decrypted plaintext
    """
    try:
        # Parse the packet
        # First, extract the ephemeral public key (R)
        # We need to determine its length by trying to deserialize it
        for i in range(65, 160):  # Try different lengths for R
            try:
                R_bytes = packet[:i]
                R = serialization.load_der_public_key(
                    R_bytes,
                    backend=default_backend()
                )
                # If we get here, we've successfully parsed R
                break
            except Exception:
                continue
        else:
            raise ValueError("Could not parse ephemeral public key from packet")
        
        # Extract nonce and ciphertext
        nonce = packet[i:i+12]
        ciphertext_with_tag = packet[i+12:]
        
        # Compute shared secret: kb·R
        shared_secret = private_key.exchange(
            ec.ECDH(),
            R
        )
        
        # Derive encryption and MAC keys
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=48,  # 32 bytes for AES-256 + 16 bytes for MAC
            salt=None,
            info=b'ECIES',
            backend=default_backend()
        ).derive(shared_secret)
        
        encryption_key = derived_key[:32]
        mac_key = derived_key[32:48]
        
        # Decrypt with AES-GCM (verification of tag is automatic)
        aesgcm = AESGCM(encryption_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
            return plaintext
        except Exception:
            raise ValueError("Decryption failed: Invalid ciphertext or tag")
        
    except Exception as e:
        raise RuntimeError(f"Decryption failed: {str(e)}")
