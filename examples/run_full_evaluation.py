"""
Example script for running a complete evaluation of both steganography and cryptography.
"""
import os
import sys
import argparse
import json
from datetime import datetime

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import local modules
import ecies
import dwt_stego
import metrics


def main():
    """Run a complete evaluation of steganography and cryptography."""
    parser = argparse.ArgumentParser(description='Run complete evaluation')
    parser.add_argument('--original-wav', required=True, help='Path to original WAV file')
    parser.add_argument('--stego-wav', required=True, help='Path to stego WAV file')
    parser.add_argument('--original-data', required=True, help='Path to original data file')
    parser.add_argument('--extracted-data', required=True, help='Path to extracted data file')
    parser.add_argument('--curve', default='secp256r1', 
                        choices=['secp256r1', 'secp384r1', 'secp521r1', 'secp256k1'],
                        help='Elliptic curve to use')
    parser.add_argument('--data-size', type=int, default=1024, help='Data size in bytes for crypto tests')
    parser.add_argument('--trials', type=int, default=100, help='Number of trials for crypto tests')
    parser.add_argument('--output', default='evaluation_results.json', help='Output file for results')
    parser.add_argument('--plot', action='store_true', help='Generate plots')
    
    args = parser.parse_args()
    
    try:
        results = {
            "evaluation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "steganography": {},
            "cryptography": {}
        }
        
        print("\n=== Running Complete Evaluation ===")
        
        # Evaluate steganography
        print("\n--- Steganography Evaluation ---")
        
        # Read original and extracted data
        with open(args.original_data, 'rb') as f:
            original_bytes = f.read()
        
        with open(args.extracted_data, 'rb') as f:
            extracted_bytes = f.read()
        
        # Compute steganography metrics
        snr = metrics.compute_snr(args.original_wav, args.stego_wav)
        ber = metrics.compute_ber(original_bytes, extracted_bytes)
        
        # Store steganography results
        results["steganography"] = {
            "snr": snr,
            "ber": ber,
            "original_wav": args.original_wav,
            "stego_wav": args.stego_wav,
            "original_data_size": len(original_bytes),
            "extracted_data_size": len(extracted_bytes)
        }
        
        # Print steganography results
        print(f"Signal-to-Noise Ratio (SNR): {snr:.2f} dB")
        print(f"Bit Error Rate (BER): {ber:.6f}")
        
        # Generate plots if requested
        if args.plot:
            print("\nGenerating plots...")
            metrics.plot_metrics(args.original_wav, args.stego_wav, original_bytes, extracted_bytes)
            results["steganography"]["plot_file"] = "stego_metrics.png"
        
        # Print MOS instructions
        print("\nNote: For MOS evaluation, run 'python -m cli eval-mos' separately.")
        
        # Evaluate cryptography
        print("\n--- Cryptography Evaluation ---")
        
        # Generate random data for crypto tests
        data = os.urandom(args.data_size)
        
        # Generate key pair
        private_pem, public_pem = ecies.generate_keypair(args.curve)
        
        # Save keys temporarily
        with open('temp_private.pem', 'wb') as f:
            f.write(private_pem)
        with open('temp_public.pem', 'wb') as f:
            f.write(public_pem)
        
        # Load keys
        priv_key = ecies.load_private_key('temp_private.pem')
        pub_key = ecies.load_public_key('temp_public.pem')
        
        # Encrypt data once for decryption test
        ciphertext = ecies.encrypt_ecies(pub_key, data)
        
        # Compute cryptography metrics
        keygen_time = metrics.compute_keygen_time(args.curve, args.trials)
        enc_time = metrics.compute_enc_time(pub_key, data, args.trials)
        dec_time = metrics.compute_dec_time(priv_key, ciphertext, args.trials)
        expansion = metrics.compute_expansion_ratio(data, ciphertext)
        avalanche = metrics.compute_avalanche(pub_key, data, args.trials)
        throughput = metrics.compute_throughput(pub_key, data, args.trials)
        
        # Store cryptography results
        results["cryptography"] = {
            "curve": args.curve,
            "data_size": args.data_size,
            "trials": args.trials,
            "key_generation_time_ms": keygen_time,
            "encryption_time_ms": enc_time,
            "decryption_time_ms": dec_time,
            "expansion_ratio": expansion,
            "avalanche_effect_percent": avalanche,
            "throughput_mbps": throughput
        }
        
        # Print cryptography results
        print(f"Curve: {args.curve}")
        print(f"Data size: {args.data_size} bytes")
        print(f"Trials: {args.trials}")
        print(f"Key generation time: {keygen_time:.2f} ms")
        print(f"Encryption time: {enc_time:.2f} ms")
        print(f"Decryption time: {dec_time:.2f} ms")
        print(f"Expansion ratio: {expansion:.2f}x")
        print(f"Avalanche effect: {avalanche:.2f}%")
        print(f"Throughput: {throughput:.2f} Mbps")
        
        # Clean up temporary files
        os.remove('temp_private.pem')
        os.remove('temp_public.pem')
        
        # Save results to file
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=4)
        
        print(f"\nEvaluation results saved to {args.output}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
