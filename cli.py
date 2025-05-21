"""
Command-line interface for the ECIES-DWT toolkit.
"""
import os
import sys
import time
import click
import numpy as np
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

# Import local modules
import ecies
import dwt_stego
import metrics


@click.group()
def cli():
    """ECIES-DWT Toolkit: Secure audio steganography using ECC and DWT."""
    pass


@cli.command('genkeys')
@click.option('--curve', default='secp256r1', 
              type=click.Choice(['secp256r1', 'secp384r1', 'secp521r1', 'secp256k1']),
              help='Elliptic curve to use')
@click.option('--private-key', default='private_key.pem', help='Path to save private key')
@click.option('--public-key', default='public_key.pem', help='Path to save public key')
def genkeys(curve: str, private_key: str, public_key: str):
    """Generate ECC key pair."""
    try:
        click.echo(f"Generating {curve} key pair...")
        
        # Generate key pair
        private_pem, public_pem = ecies.generate_keypair(curve)
        
        # Save keys
        ecies.save_keys(private_pem, public_pem, private_key, public_key)
        
        click.echo(f"Private key saved to: {private_key}")
        click.echo(f"Public key saved to: {public_key}")
        
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command('encrypt')
@click.option('--public-key', required=True, help='Path to public key')
@click.option('--input-file', required=True, help='Path to input file')
@click.option('--output-file', required=True, help='Path to output file')
def encrypt(public_key: str, input_file: str, output_file: str):
    """Encrypt a file using ECIES."""
    try:
        # Load public key
        pub_key = ecies.load_public_key(public_key)
        
        # Read input file
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        click.echo(f"Encrypting {len(plaintext)} bytes...")
        
        # Encrypt data
        ciphertext = ecies.encrypt_ecies(pub_key, plaintext)
        
        # Write output file
        with open(output_file, 'wb') as f:
            f.write(ciphertext)
        
        # Calculate expansion ratio
        expansion = len(ciphertext) / len(plaintext)
        
        click.echo(f"Encrypted data saved to: {output_file}")
        click.echo(f"Original size: {len(plaintext)} bytes")
        click.echo(f"Encrypted size: {len(ciphertext)} bytes")
        click.echo(f"Expansion ratio: {expansion:.2f}x")
        
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command('decrypt')
@click.option('--private-key', required=True, help='Path to private key')
@click.option('--input-file', required=True, help='Path to encrypted file')
@click.option('--output-file', required=True, help='Path to output file')
def decrypt(private_key: str, input_file: str, output_file: str):
    """Decrypt a file using ECIES."""
    try:
        # Load private key
        priv_key = ecies.load_private_key(private_key)
        
        # Read encrypted file
        with open(input_file, 'rb') as f:
            ciphertext = f.read()
        
        click.echo(f"Decrypting {len(ciphertext)} bytes...")
        
        # Decrypt data
        plaintext = ecies.decrypt_ecies(priv_key, ciphertext)
        
        # Write output file
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        
        click.echo(f"Decrypted data saved to: {output_file}")
        click.echo(f"Decrypted size: {len(plaintext)} bytes")
        
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command('embed')
@click.option('--public-key', required=True, help='Path to public key')
@click.option('--cover-wav', required=True, help='Path to cover WAV file')
@click.option('--stego-wav', required=True, help='Path to output stego WAV file')
@click.option('--input-file', required=True, help='Path to input file to embed')
@click.option('--wavelet', default='haar', help='Wavelet to use')
@click.option('--level', default=4, help='DWT decomposition level')
@click.option('--coeff-band', default='detail', type=click.Choice(['detail', 'approximation']),
              help='Coefficient band to use')
@click.option('--alpha', default=0.05, help='Embedding strength')
def embed(public_key: str, cover_wav: str, stego_wav: str, input_file: str,
          wavelet: str, level: int, coeff_band: str, alpha: float):
    """Encrypt and embed data in audio using ECIES and DWT."""
    try:
        # Load public key
        pub_key = ecies.load_public_key(public_key)
        
        # Read input file
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        click.echo(f"Encrypting {len(plaintext)} bytes...")
        
        # Encrypt data
        ciphertext = ecies.encrypt_ecies(pub_key, plaintext)
        
        click.echo(f"Embedding {len(ciphertext)} bytes in audio...")
        
        # Embed encrypted data in audio
        dwt_stego.embed_dwt(cover_wav, stego_wav, ciphertext, wavelet, level, coeff_band, alpha)
        
        # Calculate metrics
        snr = metrics.compute_snr(cover_wav, stego_wav)
        
        click.echo(f"Data embedded successfully.")
        click.echo(f"Stego audio saved to: {stego_wav}")
        click.echo(f"SNR: {snr:.2f} dB")
        
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command('extract')
@click.option('--private-key', required=True, help='Path to private key')
@click.option('--stego-wav', required=True, help='Path to stego WAV file')
@click.option('--output-file', required=True, help='Path to output file')
@click.option('--wavelet', default='haar', help='Wavelet to use')
@click.option('--level', default=4, help='DWT decomposition level')
@click.option('--coeff-band', default='detail', type=click.Choice(['detail', 'approximation']),
              help='Coefficient band to use')
@click.option('--alpha', default=0.05, help='Embedding strength')
def extract(private_key: str, stego_wav: str, output_file: str,
            wavelet: str, level: int, coeff_band: str, alpha: float):
    """Extract and decrypt data from audio using DWT and ECIES."""
    try:
        # Load private key
        priv_key = ecies.load_private_key(private_key)
        
        click.echo(f"Extracting data from audio...")
        
        # Extract data from audio
        ciphertext = dwt_stego.extract_dwt(stego_wav, wavelet, level, coeff_band, alpha)
        
        click.echo(f"Decrypting {len(ciphertext)} bytes...")
        
        # Decrypt data
        plaintext = ecies.decrypt_ecies(priv_key, ciphertext)
        
        # Write output file
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        
        click.echo(f"Data extracted and decrypted successfully.")
        click.echo(f"Output saved to: {output_file}")
        
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command('eval-stego')
@click.option('--original-wav', required=True, help='Path to original WAV file')
@click.option('--stego-wav', required=True, help='Path to stego WAV file')
@click.option('--original-data', required=True, help='Path to original data file')
@click.option('--extracted-data', required=True, help='Path to extracted data file')
@click.option('--plot', is_flag=True, help='Generate plots')
def eval_stego(original_wav: str, stego_wav: str, original_data: str, extracted_data: str, plot: bool):
    """Evaluate steganography performance."""
    try:
        # Read original and extracted data
        with open(original_data, 'rb') as f:
            original_bytes = f.read()
        
        with open(extracted_data, 'rb') as f:
            extracted_bytes = f.read()
        
        # Compute metrics
        snr = metrics.compute_snr(original_wav, stego_wav)
        ber = metrics.compute_ber(original_bytes, extracted_bytes)
        
        # Print results
        click.echo("\n=== Steganography Evaluation ===")
        click.echo(f"Signal-to-Noise Ratio (SNR): {snr:.2f} dB")
        click.echo(f"Bit Error Rate (BER): {ber:.6f}")
        
        # Print MOS instructions
        metrics.print_mos_instructions()
        
        # Generate plots if requested
        if plot:
            click.echo("\nGenerating plots...")
            metrics.plot_metrics(original_wav, stego_wav, original_bytes, extracted_bytes)
        
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command('eval-mos')
@click.option('--original-wav', required=True, help='Path to original WAV file')
@click.option('--stego-wav', required=True, help='Path to stego WAV file')
@click.option('--listeners', default=1, help='Number of listeners')
def eval_mos(original_wav: str, stego_wav: str, listeners: int):
    """Conduct Mean Opinion Score (MOS) evaluation."""
    try:
        # Import here to avoid circular imports
        import mos_eval
        
        # Run MOS test
        mos_eval.conduct_mos_test(original_wav, stego_wav, listeners)
        
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command('eval-crypto')
@click.option('--curve', default='secp256r1', 
              type=click.Choice(['secp256r1', 'secp384r1', 'secp521r1', 'secp256k1']),
              help='Elliptic curve to use')
@click.option('--data-size', default=1024, help='Data size in bytes')
@click.option('--trials', default=100, help='Number of trials')
def eval_crypto(curve: str, data_size: int, trials: int):
    """Evaluate cryptography performance."""
    try:
        # Generate random data
        data = os.urandom(data_size)
        
        # Generate key pair
        private_pem, public_pem = ecies.generate_keypair(curve)
        priv_key = ecies.load_private_key('private_key.pem')
        pub_key = ecies.load_public_key('public_key.pem')
        
        # Encrypt data once for decryption test
        ciphertext = ecies.encrypt_ecies(pub_key, data)
        
        # Compute metrics
        keygen_time = metrics.compute_keygen_time(curve, trials)
        enc_time = metrics.compute_enc_time(pub_key, data, trials)
        dec_time = metrics.compute_dec_time(priv_key, ciphertext, trials)
        expansion = metrics.compute_expansion_ratio(data, ciphertext)
        avalanche = metrics.compute_avalanche(pub_key, data, trials)
        throughput = metrics.compute_throughput(pub_key, data, trials)
        
        # Print results
        click.echo("\n=== Cryptography Evaluation ===")
        click.echo(f"Curve: {curve}")
        click.echo(f"Data size: {data_size} bytes")
        click.echo(f"Trials: {trials}")
        click.echo(f"Key generation time: {keygen_time:.2f} ms")
        click.echo(f"Encryption time: {enc_time:.2f} ms")
        click.echo(f"Decryption time: {dec_time:.2f} ms")
        click.echo(f"Expansion ratio: {expansion:.2f}x")
        click.echo(f"Avalanche effect: {avalanche:.2f}%")
        click.echo(f"Throughput: {throughput:.2f} Mbps")
        
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    cli()
