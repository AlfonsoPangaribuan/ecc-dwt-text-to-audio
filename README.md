# Encrypted Text Protection Using ECC in Audio via Discrete Wavelet Transform (DWT)

A Python toolkit for secure steganography using Elliptic Curve Integrated Encryption Scheme (ECIES) and Discrete Wavelet Transform (DWT) for embedding encrypted data in audio files.

## Features

- **True ECIES Encryption**: Implements full ECIES with ephemeral EC key, AES-GCM encryption, and MAC authentication
- **Robust Audio Steganography**: Uses DWT for embedding data in audio files with minimal perceptual impact
- **Comprehensive Metrics**: Includes tools for evaluating both steganography (SNR, BER, MOS) and cryptography (timings, entropy, avalanche)
- **Easy-to-Use CLI**: Simple command-line interface for all operations

## Installation

1. Clone the repository:
   \`\`\`
   git clone https://github.com/yourusername/ecies-dwt-toolkit.git
   cd ecies-dwt-toolkit
   \`\`\`

2. Install dependencies:
   \`\`\`
   pip install -r requirements.txt
   \`\`\`

## Usage

### Key Generation

Generate an ECC key pair:

\`\`\`
python -m cli genkeys --curve secp256r1 --private-key private_key.pem --public-key public_key.pem
\`\`\`

### Encryption and Embedding

Encrypt data and embed it in an audio file:

\`\`\`
python -m cli embed --public-key public_key.pem --cover-wav cover.wav --stego-wav stego.wav --input-file secret.txt
\`\`\`

### Extraction and Decryption

Extract and decrypt data from a stego audio file:

\`\`\`
python -m cli extract --private-key private_key.pem --stego-wav stego.wav --output-file extracted.txt
\`\`\`

### Evaluation

Evaluate steganography performance:

\`\`\`
python -m cli eval-stego --original-wav cover.wav --stego-wav stego.wav --original-data secret.txt --extracted-data extracted.txt --plot
\`\`\`

Evaluate cryptography performance:

\`\`\`
python -m cli eval-crypto --curve secp256r1 --data-size 1024 --trials 100
\`\`\`

## Technical Details

### ECIES Implementation

The ECIES implementation follows these steps:

1. Generate ephemeral EC key pair (r, R = r·G)
2. Compute shared secret (r·Kb)
3. Derive encryption and MAC keys using HKDF-SHA256
4. Encrypt plaintext using AES-GCM
5. Return the complete packet: R || nonce || ciphertext || tag

### DWT Steganography

The DWT-based steganography works as follows:

1. Apply DWT to the audio signal
2. Modify wavelet coefficients to embed data
3. Apply inverse DWT to reconstruct the audio signal

## Examples

Example scripts are provided in the `examples` directory:

- `generate_keys.py`: Generate ECC key pair
- `encrypt_and_embed.py`: Encrypt data and embed it in audio
- `extract_and_decrypt.py`: Extract and decrypt data from audio

## License

This project is licensed under the MIT License - see the LICENSE file for details.
