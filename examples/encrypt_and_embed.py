"""
Example script for encrypting data and embedding it in audio.
"""
import os
import sys
import argparse

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import local modules
import ecies
import dwt_stego
import metrics


def main():
    """Encrypt data and embed it in audio."""
    parser = argparse.ArgumentParser(description='Encrypt data and embed it in audio')
    parser.add_argument('--public-key', required=True, help='Path to public key')
    parser.add_argument('--cover-wav', required=True, help='Path to cover WAV file')
    parser.add_argument('--stego-wav', required=True, help='Path to output stego WAV file')
    parser.add_argument('--input-file', required=True, help='Path to input file to embed')
    parser.add_argument('--wavelet', default='haar', help='Wavelet to use')
    parser.add_argument('--level', type=int, default=4, help='DWT decomposition level')
    parser.add_argument('--coeff-band', default='detail', choices=['detail', 'approximation'],
                        help='Coefficient band to use')
    parser.add_argument('--alpha', type=float, default=0.05, help='Embedding strength')
    
    args = parser.parse_args()
    
    try:
        # Load public key
        pub_key = ecies.load_public_key(args.public_key)
        
        # Read input file
        with open(args.input_file, 'rb') as f:
            plaintext = f.read()
        
        print(f"Encrypting {len(plaintext)} bytes...")
        
        # Encrypt data
        ciphertext = ecies.encrypt_ecies(pub_key, plaintext)
        
        print(f"Embedding {len(ciphertext)} bytes in audio...")
        
        # Embed encrypted data in audio
        dwt_stego.embed_dwt(args.cover_wav, args.stego_wav, ciphertext, 
                           args.wavelet, args.level, args.coeff_band, args.alpha)
        
        # Calculate metrics
        snr = metrics.compute_snr(args.cover_wav, args.stego_wav)
        
        print(f"Data embedded successfully.")
        print(f"Stego audio saved to: {args.stego_wav}")
        print(f"SNR: {snr:.2f} dB")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
