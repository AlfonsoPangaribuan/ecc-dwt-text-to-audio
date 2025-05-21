"""
Audio steganography using Discrete Wavelet Transform (DWT).
"""
import numpy as np
import pywt
import wave
import struct
import math
from typing import Tuple, List, Optional


def read_wav(wav_path: str) -> Tuple[np.ndarray, int, int]:
    """
    Read a WAV file and extract PCM signal.
    
    Args:
        wav_path: Path to WAV file
        
    Returns:
        Tuple containing (audio_data, sample_rate, num_channels)
    """
    try:
        with wave.open(wav_path, 'rb') as wav_file:
            num_channels = wav_file.getnchannels()
            sample_width = wav_file.getsampwidth()
            sample_rate = wav_file.getframerate()
            num_frames = wav_file.getnframes()
            
            # Read all frames
            frames = wav_file.readframes(num_frames)
            
            # Convert to numpy array based on sample width
            if sample_width == 1:  # 8-bit samples
                fmt = f"{num_frames * num_channels}B"
                audio_data = np.array(struct.unpack(fmt, frames), dtype=np.uint8)
                audio_data = (audio_data.astype(np.float32) - 128) / 128.0
            elif sample_width == 2:  # 16-bit samples
                fmt = f"{num_frames * num_channels}h"
                audio_data = np.array(struct.unpack(fmt, frames), dtype=np.int16)
                audio_data = audio_data.astype(np.float32) / 32768.0
            elif sample_width == 3:  # 24-bit samples
                # Handle 24-bit samples by converting to 32-bit
                audio_data = np.zeros(num_frames * num_channels, dtype=np.float32)
                for i in range(num_frames * num_channels):
                    audio_data[i] = (frames[i*3] | (frames[i*3+1] << 8) | (frames[i*3+2] << 16)) / 8388608.0
                    if audio_data[i] >= 1.0:
                        audio_data[i] -= 2.0
            elif sample_width == 4:  # 32-bit samples
                fmt = f"{num_frames * num_channels}i"
                audio_data = np.array(struct.unpack(fmt, frames), dtype=np.int32)
                audio_data = audio_data.astype(np.float32) / 2147483648.0
            else:
                raise ValueError(f"Unsupported sample width: {sample_width}")
            
            # Reshape for multi-channel audio
            if num_channels > 1:
                audio_data = audio_data.reshape(-1, num_channels)
            
            return audio_data, sample_rate, num_channels
            
    except Exception as e:
        raise RuntimeError(f"Failed to read WAV file: {str(e)}")


def write_wav(wav_path: str, audio_data: np.ndarray, sample_rate: int, num_channels: int) -> None:
    """
    Write audio data to a WAV file.
    
    Args:
        wav_path: Path to output WAV file
        audio_data: Audio data as numpy array
        sample_rate: Sample rate in Hz
        num_channels: Number of audio channels
    """
    try:
        # Ensure audio data is in the correct range [-1, 1]
        audio_data = np.clip(audio_data, -1.0, 1.0)
        
        # Convert to 16-bit PCM
        audio_data = (audio_data * 32767).astype(np.int16)
        
        # Flatten multi-channel audio
        if len(audio_data.shape) > 1 and audio_data.shape[1] > 1:
            audio_data = audio_data.flatten()
        
        with wave.open(wav_path, 'wb') as wav_file:
            wav_file.setnchannels(num_channels)
            wav_file.setsampwidth(2)  # 16-bit
            wav_file.setframerate(sample_rate)
            
            # Pack audio data
            packed_data = struct.pack(f"{len(audio_data)}h", *audio_data)
            wav_file.writeframes(packed_data)
            
    except Exception as e:
        raise RuntimeError(f"Failed to write WAV file: {str(e)}")


def bytes_to_bits(data: bytes) -> List[int]:
    """
    Convert bytes to a list of bits.
    
    Args:
        data: Bytes to convert
        
    Returns:
        List of bits (0s and 1s)
    """
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: List[int]) -> bytes:
    """
    Convert a list of bits to bytes.
    
    Args:
        bits: List of bits (0s and 1s)
        
    Returns:
        Bytes object
    """
    # Ensure the number of bits is a multiple of 8
    while len(bits) % 8 != 0:
        bits.append(0)
        
    bytes_data = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= (bits[i + j] << j)
        bytes_data.append(byte)
        
    return bytes(bytes_data)


def embed_dwt(cover_wav: str, stego_wav: str, data: bytes,
              wavelet: str = 'haar', level: int = 4, 
              coeff_band: str = 'detail', alpha: float = 0.05) -> None:
    """
    Embed data in audio using DWT.
    
    Args:
        cover_wav: Path to cover WAV file
        stego_wav: Path to output stego WAV file
        data: Data to embed
        wavelet: Wavelet to use (default: 'haar')
        level: DWT decomposition level (default: 4)
        coeff_band: Coefficient band to use ('detail' or 'approximation')
        alpha: Embedding strength (default: 0.05)
    """
    try:
        # Read cover audio
        audio_data, sample_rate, num_channels = read_wav(cover_wav)
        
        # Convert data to bits
        bits = bytes_to_bits(data)
        
        # Add length information (32 bits) at the beginning
        length_bits = []
        length = len(bits)
        for i in range(32):
            length_bits.append((length >> i) & 1)
        
        bits = length_bits + bits
        
        # Process each channel separately
        stego_audio = np.zeros_like(audio_data)
        
        for channel in range(num_channels):
            # Get channel data
            if num_channels > 1:
                channel_data = audio_data[:, channel]
            else:
                channel_data = audio_data
            
            # Apply DWT
            coeffs = pywt.wavedec(channel_data, wavelet, level=level)
            
            # Select coefficient band for embedding
            if coeff_band == 'detail':
                # Use the highest level detail coefficients
                target_coeffs = coeffs[1]
            else:
                # Use approximation coefficients
                target_coeffs = coeffs[0]
            
            # Check if we have enough coefficients for embedding
            if len(target_coeffs) < len(bits):
                raise ValueError(f"Not enough coefficients ({len(target_coeffs)}) to embed data ({len(bits)} bits)")
            
            # Embed bits by modifying coefficient values
            for i, bit in enumerate(bits):
                if i < len(target_coeffs):
                    # Quantize coefficient
                    coeff = target_coeffs[i]
                    sign = 1 if coeff >= 0 else -1
                    abs_coeff = abs(coeff)
                    
                    # Modify coefficient based on bit value
                    if bit == 1:
                        # Ensure coefficient is odd when quantized
                        if int(abs_coeff / alpha) % 2 == 0:
                            abs_coeff += alpha
                    else:
                        # Ensure coefficient is even when quantized
                        if int(abs_coeff / alpha) % 2 == 1:
                            abs_coeff += alpha
                    
                    # Update coefficient
                    target_coeffs[i] = sign * abs_coeff
            
            # Update coefficients
            if coeff_band == 'detail':
                coeffs[1] = target_coeffs
            else:
                coeffs[0] = target_coeffs
            
            # Apply inverse DWT
            reconstructed = pywt.waverec(coeffs, wavelet)
            
            # Handle potential length mismatch
            if len(reconstructed) > len(channel_data):
                reconstructed = reconstructed[:len(channel_data)]
            elif len(reconstructed) < len(channel_data):
                padding = np.zeros(len(channel_data) - len(reconstructed))
                reconstructed = np.concatenate([reconstructed, padding])
            
            # Store reconstructed channel
            if num_channels > 1:
                stego_audio[:, channel] = reconstructed
            else:
                stego_audio = reconstructed
        
        # Write stego audio
        write_wav(stego_wav, stego_audio, sample_rate, num_channels)
        
    except Exception as e:
        raise RuntimeError(f"Failed to embed data: {str(e)}")


def extract_dwt(stego_wav: str, wavelet: str = 'haar', level: int = 4, 
                coeff_band: str = 'detail', alpha: float = 0.05) -> bytes:
    """
    Extract embedded data from audio using DWT.
    
    Args:
        stego_wav: Path to stego WAV file
        wavelet: Wavelet to use (default: 'haar')
        level: DWT decomposition level (default: 4)
        coeff_band: Coefficient band to use ('detail' or 'approximation')
        alpha: Embedding strength (default: 0.05)
        
    Returns:
        Extracted data as bytes
    """
    try:
        # Read stego audio
        audio_data, sample_rate, num_channels = read_wav(stego_wav)
        
        # Use first channel for extraction
        if num_channels > 1:
            channel_data = audio_data[:, 0]
        else:
            channel_data = audio_data
        
        # Apply DWT
        coeffs = pywt.wavedec(channel_data, wavelet, level=level)
        
        # Select coefficient band for extraction
        if coeff_band == 'detail':
            # Use the highest level detail coefficients
            target_coeffs = coeffs[1]
        else:
            # Use approximation coefficients
            target_coeffs = coeffs[0]
        
        # Extract length information first (32 bits)
        length_bits = []
        for i in range(32):
            coeff = target_coeffs[i]
            abs_coeff = abs(coeff)
            
            # Extract bit based on coefficient quantization
            if int(abs_coeff / alpha) % 2 == 1:
                length_bits.append(1)
            else:
                length_bits.append(0)
        
        # Convert length bits to integer
        data_length = 0
        for i, bit in enumerate(length_bits):
            data_length |= (bit << i)
        
        # Extract data bits
        extracted_bits = []
        for i in range(32, 32 + data_length):
            if i < len(target_coeffs):
                coeff = target_coeffs[i]
                abs_coeff = abs(coeff)
                
                # Extract bit based on coefficient quantization
                if int(abs_coeff / alpha) % 2 == 1:
                    extracted_bits.append(1)
                else:
                    extracted_bits.append(0)
        
        # Convert bits to bytes
        extracted_data = bits_to_bytes(extracted_bits)
        
        return extracted_data
        
    except Exception as e:
        raise RuntimeError(f"Failed to extract data: {str(e)}")
