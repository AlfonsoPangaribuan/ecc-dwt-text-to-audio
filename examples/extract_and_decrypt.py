"""
Example script for extracting and decrypting data from audio.
"""
import os
import sys
import argparse

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import local modules
import ecies
import dwt_stego


def main():
    """Extract and decrypt data from audio."""
    parser = argparse.ArgumentParser(description='Extract and decrypt data from audio')
    parser.add_argument('--private-key', required=True, help='Path to private key')
    parser.add_argument('--stego-wav', required=True, help='Path to stego WAV file')
    parser.add_argument('--output-file', required=True, help='Path to output file')
    parser.add_argument('--wavelet', default='haar', help='Wavelet to use')
    parser.add_argument('--level', type=int, default=4, help='DWT decomposition level')
    parser.add_argument('--coeff-band', default='detail', choices=['detail', 'approximation'],
                        help='Coefficient band to use')
    parser.add_argument('--alpha', type=float, default=0.05, help='Embedding strength')
    
    args = parser.parse_args()
    
    try:
        # Load private key
        priv_key = ecies.load_private_key(args.private_key)
        
        print(f"Extracting data from audio...")
        
        # Extract data from audio
        ciphertext = dwt_stego.extract_dwt(args.stego_wav, args.wavelet, args.level, 
                                          args.coeff_band, args.alpha)
        
        print(f"Decrypting {len(ciphertext)} bytes...")
        
        # Decrypt data
        plaintext = ecies.decrypt_ecies(priv_key, ciphertext)
        
        # Write output file
        with open(args.output_file, 'wb') as f:
            f.write(plaintext)
        
        print(f"Data extracted and decrypted successfully.")
        print(f"Output saved to: {args.output_file}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
