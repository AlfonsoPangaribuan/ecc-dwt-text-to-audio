"""
Evaluation metrics for steganography and cryptography.
"""
import os
import time
import numpy as np
import wave
import struct
import random
from typing import Tuple, List, Optional
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

# Import local modules
import ecies
import dwt_stego


def compute_snr(original_wav: str, stego_wav: str) -> float:
    """
    Compute Signal-to-Noise Ratio (SNR) between original and stego audio.
    
    Args:
        original_wav: Path to original WAV file
        stego_wav: Path to stego WAV file
        
    Returns:
        SNR in dB
    """
    try:
        # Read original audio
        original_data, _, _ = dwt_stego.read_wav(original_wav)
        
        # Read stego audio
        stego_data, _, _ = dwt_stego.read_wav(stego_wav)
        
        # Ensure same length
        min_length = min(len(original_data), len(stego_data))
        original_data = original_data[:min_length]
        stego_data = stego_data[:min_length]
        
        # Flatten multi-channel audio if needed
        if len(original_data.shape) > 1 and original_data.shape[1] > 1:
            original_flat = original_data.flatten()
            stego_flat = stego_data.flatten()
        else:
            original_flat = original_data
            stego_flat = stego_data
        
        # Compute SNR
        signal_power = np.sum(original_flat ** 2)
        noise_power = np.sum((original_flat - stego_flat) ** 2)
        
        if noise_power == 0:
            return float('inf')  # Perfect reconstruction
            
        snr = 10 * np.log10(signal_power / noise_power)
        
        return snr
        
    except Exception as e:
        raise RuntimeError(f"Failed to compute SNR: {str(e)}")


def compute_ber(original_bits: bytes, extracted_bits: bytes) -> float:
    """
    Compute Bit Error Rate (BER) between original and extracted bits.
    
    Args:
        original_bits: Original data
        extracted_bits: Extracted data
        
    Returns:
        BER as a fraction
    """
    try:
        # Convert bytes to bits
        original = dwt_stego.bytes_to_bits(original_bits)
        extracted = dwt_stego.bytes_to_bits(extracted_bits)
        
        # Ensure same length
        min_length = min(len(original), len(extracted))
        original = original[:min_length]
        extracted = extracted[:min_length]
        
        # Count bit errors
        errors = sum(1 for i in range(min_length) if original[i] != extracted[i])
        
        # Compute BER
        ber = errors / min_length if min_length > 0 else 0
        
        return ber
        
    except Exception as e:
        raise RuntimeError(f"Failed to compute BER: {str(e)}")


def print_mos_instructions() -> None:
    """
    Print instructions for Mean Opinion Score (MOS) testing.
    """
    print("\n=== Mean Opinion Score (MOS) Testing Instructions ===")
    print("MOS is a subjective quality measure for audio, rated on a scale of 1-5:")
    print("5 - Excellent: Imperceptible difference from original")
    print("4 - Good: Perceptible but not annoying")
    print("3 - Fair: Slightly annoying")
    print("2 - Poor: Annoying")
    print("1 - Bad: Very annoying")
    print("\nTo conduct MOS testing:")
    print("1. Gather at least 10 listeners")
    print("2. Play both original and stego audio samples in random order")
    print("3. Ask listeners to rate the quality of each sample")
    print("4. Calculate the average score for stego samples")
    print("\nNote: Blind testing is recommended to avoid bias.")


def compute_keygen_time(curve: str = 'secp256r1', trials: int = 100) -> float:
    """
    Measure key generation time.
    
    Args:
        curve: Elliptic curve to use
        trials: Number of trials
        
    Returns:
        Average key generation time in milliseconds
    """
    try:
        total_time = 0
        
        for _ in range(trials):
            start_time = time.time()
            ecies.generate_keypair(curve)
            end_time = time.time()
            
            total_time += (end_time - start_time) * 1000  # Convert to ms
            
        avg_time = total_time / trials
        
        return avg_time
        
    except Exception as e:
        raise RuntimeError(f"Failed to compute key generation time: {str(e)}")


def compute_enc_time(pub_key: ec.EllipticCurvePublicKey, data: bytes, trials: int = 100) -> float:
    """
    Measure encryption time.
    
    Args:
        pub_key: Public key
        data: Data to encrypt
        trials: Number of trials
        
    Returns:
        Average encryption time in milliseconds
    """
    try:
        total_time = 0
        
        for _ in range(trials):
            start_time = time.time()
            ecies.encrypt_ecies(pub_key, data)
            end_time = time.time()
            
            total_time += (end_time - start_time) * 1000  # Convert to ms
            
        avg_time = total_time / trials
        
        return avg_time
        
    except Exception as e:
        raise RuntimeError(f"Failed to compute encryption time: {str(e)}")


def compute_dec_time(priv_key: ec.EllipticCurvePrivateKey, packet: bytes, trials: int = 100) -> float:
    """
    Measure decryption time.
    
    Args:
        priv_key: Private key
        packet: Encrypted packet
        trials: Number of trials
        
    Returns:
        Average decryption time in milliseconds
    """
    try:
        total_time = 0
        
        for _ in range(trials):
            start_time = time.time()
            ecies.decrypt_ecies(priv_key, packet)
            end_time = time.time()
            
            total_time += (end_time - start_time) * 1000  # Convert to ms
            
        avg_time = total_time / trials
        
        return avg_time
        
    except Exception as e:
        raise RuntimeError(f"Failed to compute decryption time: {str(e)}")


def compute_expansion_ratio(data: bytes, ciphertext: bytes) -> float:
    """
    Compute expansion ratio of ciphertext compared to plaintext.
    
    Args:
        data: Original data
        ciphertext: Encrypted data
        
    Returns:
        Expansion ratio
    """
    try:
        return len(ciphertext) / len(data)
        
    except Exception as e:
        raise RuntimeError(f"Failed to compute expansion ratio: {str(e)}")


def compute_avalanche(pub_key: ec.EllipticCurvePublicKey, data: bytes, trials: int = 100) -> float:
    """
    Compute avalanche effect (bit changes in output when input changes by 1 bit).
    
    Args:
        pub_key: Public key
        data: Data to encrypt
        trials: Number of trials
        
    Returns:
        Average percentage of bits changed
    """
    try:
        total_percentage = 0
        
        for _ in range(trials):
            # Encrypt original data
            ciphertext1 = ecies.encrypt_ecies(pub_key, data)
            
            # Modify one random bit in the data
            data_list = bytearray(data)
            bit_pos = random.randint(0, len(data) * 8 - 1)
            byte_pos = bit_pos // 8
            bit_in_byte = bit_pos % 8
            data_list[byte_pos] ^= (1 << bit_in_byte)
            
            # Encrypt modified data
            ciphertext2 = ecies.encrypt_ecies(pub_key, bytes(data_list))
            
            # Count differing bits
            min_length = min(len(ciphertext1), len(ciphertext2))
            diff_bits = 0
            
            for i in range(min_length):
                xor_result = ciphertext1[i] ^ ciphertext2[i]
                diff_bits += bin(xor_result).count('1')
            
            # Calculate percentage of bits changed
            percentage = (diff_bits / (min_length * 8)) * 100
            total_percentage += percentage
            
        avg_percentage = total_percentage / trials
        
        return avg_percentage
        
    except Exception as e:
        raise RuntimeError(f"Failed to compute avalanche effect: {str(e)}")


def compute_throughput(pub_key: ec.EllipticCurvePublicKey, data: bytes, trials: int = 100) -> float:
    """
    Compute encryption throughput.
    
    Args:
        pub_key: Public key
        data: Data to encrypt
        trials: Number of trials
        
    Returns:
        Throughput in Mbps
    """
    try:
        total_time = 0
        
        for _ in range(trials):
            start_time = time.time()
            ecies.encrypt_ecies(pub_key, data)
            end_time = time.time()
            
            total_time += (end_time - start_time)
            
        avg_time = total_time / trials
        
        # Calculate throughput in Mbps
        throughput = (len(data) * 8) / (avg_time * 1_000_000)
        
        return throughput
        
    except Exception as e:
        raise RuntimeError(f"Failed to compute throughput: {str(e)}")


def plot_metrics(original_wav: str, stego_wav: str, data: bytes, extracted_data: bytes) -> None:
    """
    Plot various metrics for visual comparison.
    
    Args:
        original_wav: Path to original WAV file
        stego_wav: Path to stego WAV file
        data: Original data
        extracted_data: Extracted data
    """
    try:
        # Read audio files
        original_data, sample_rate, num_channels = dwt_stego.read_wav(original_wav)
        stego_data, _, _ = dwt_stego.read_wav(stego_wav)
        
        # Ensure same length
        min_length = min(len(original_data), len(stego_data))
        original_data = original_data[:min_length]
        stego_data = stego_data[:min_length]
        
        # For multi-channel audio, use only the first channel for plotting
        if len(original_data.shape) > 1 and original_data.shape[1] > 1:
            original_plot_data = original_data[:, 0]
            stego_plot_data = stego_data[:, 0]
        else:
            original_plot_data = original_data
            stego_plot_data = stego_data
        
        # Create time axis
        time_axis = np.arange(len(original_plot_data)) / sample_rate
        
        # Create figure
        plt.figure(figsize=(12, 10))
        
        # Plot waveforms
        plt.subplot(3, 1, 1)
        plt.plot(time_axis, original_plot_data, 'b-', alpha=0.7, label='Original')
        plt.plot(time_axis, stego_plot_data, 'r-', alpha=0.7, label='Stego')
        plt.title('Waveform Comparison (First Channel)')
        plt.xlabel('Time (s)')
        plt.ylabel('Amplitude')
        plt.legend()
        plt.grid(True)
        
        # Plot difference
        plt.subplot(3, 1, 2)
        plt.plot(time_axis, stego_plot_data - original_plot_data, 'g-')
        plt.title('Difference (Stego - Original)')
        plt.xlabel('Time (s)')
        plt.ylabel('Amplitude Difference')
        plt.grid(True)
        
        # Plot spectrogram of difference
        plt.subplot(3, 1, 3)
        plt.specgram(stego_plot_data - original_plot_data, NFFT=1024, Fs=sample_rate, noverlap=512)
        plt.title('Spectrogram of Difference')
        plt.xlabel('Time (s)')
        plt.ylabel('Frequency (Hz)')
        
        # Compute metrics
        snr_value = compute_snr(original_wav, stego_wav)
        ber_value = compute_ber(data, extracted_data)
        
        # Add metrics as text
        plt.figtext(0.5, 0.01, f'SNR: {snr_value:.2f} dB, BER: {ber_value:.6f}', 
                   ha='center', fontsize=12, bbox={'facecolor': 'white', 'alpha': 0.8, 'pad': 5})
        
        plt.tight_layout(rect=[0, 0.03, 1, 0.95])
        plt.savefig('stego_metrics.png')
        plt.close()
        
        print(f"Metrics plot saved as 'stego_metrics.png'")
        
    except Exception as e:
        raise RuntimeError(f"Failed to plot metrics: {str(e)}")
