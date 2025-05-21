"""
Example script for generating ECC key pair.
"""
import os
import sys
import argparse

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import local modules
import ecies


def main():
    """Generate ECC key pair."""
    parser = argparse.ArgumentParser(description='Generate ECC key pair')
    parser.add_argument('--curve', default='secp256r1', 
                        choices=['secp256r1', 'secp384r1', 'secp521r1', 'secp256k1'],
                        help='Elliptic curve to use')
    parser.add_argument('--private-key', default='private_key.pem', help='Path to save private key')
    parser.add_argument('--public-key', default='public_key.pem', help='Path to save public key')
    
    args = parser.parse_args()
    
    try:
        print(f"Generating {args.curve} key pair...")
        
        # Generate key pair
        private_pem, public_pem = ecies.generate_keypair(args.curve)
        
        # Save keys
        ecies.save_keys(private_pem, public_pem, args.private_key, args.public_key)
        
        print(f"Private key saved to: {args.private_key}")
        print(f"Public key saved to: {args.public_key}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
