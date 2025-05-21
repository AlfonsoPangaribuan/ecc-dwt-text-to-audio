#  **README: Keamanan Data Terenkripsi dengan ECC & DWT Audio**

##  Identitas Kelompok 3

* **Anggota**:

  * Alfonso Pangaribuan (122140206)
  * Handayani (122140166)
  * Luthfianya Isyathun Rodiyyah (122140185)

##  Deskripsi Singkat

Toolkit Python ini menghadirkan solusi keamanan data tingkat lanjut dengan:

1. **ECIES (Elliptic Curve Integrated Encryption Scheme)** untuk enkripsi teks yang efisien dan aman,
2. **AES-GCM** untuk menjaga kerahasiaan sekaligus integritas, dan
3. **Steganografi DWT (Discrete Wavelet Transform)** untuk menyembunyikan data terenkripsi ke dalam file audio tanpa merusak kualitas.

> “Menggabungkan kriptografi mutakhir dan teknik steganografi cerdas untuk menjaga rahasia Anda.”

##  Fitur Utama

*  **ECIES Lengkap**: Enkripsi hybrid dengan ephemeral key ECC + AES-GCM + MAC
*  **Steganografi Audio Berbasis DWT**: Embed payload terenkripsi dengan gangguan minimal pada audio
*  **Evaluasi Komprehensif**:

  * **Steganografi**: SNR (Signal-to-Noise Ratio), BER (Bit Error Rate), MOS (Mean Opinion Score)
  * **Kriptografi**: Waktu generate key, encryption/decryption, expansion ratio, avalanche effect, throughput
*  **CLI Simpel**: Perintah intuitif untuk genkeys, embed, extract, dan evaluasi

##  Instalasi

```bash
# Clone repositori
git clone https://github.com/yourusername/ecies-dwt-toolkit.git
cd ecies-dwt-toolkit

# Install dependency
pip install -r requirements.txt
```

## ⚙️ Cara Penggunaan

1. **Generate Key Pair**

   ```bash
   python -m cli genkeys \
     --curve secp256r1 \
     --private-key private_key.pem \
     --public-key public_key.pem
   ```

2. **Encrypt & Embed**

   ```bash
   python -m cli embed \
     --public-key public_key.pem \
     --cover-wav cover.wav \
     --stego-wav stego.wav \
     --input-file secret.txt
   ```

3. **Extract & Decrypt**

   ```bash
   python -m cli extract \
     --private-key private_key.pem \
     --stego-wav stego.wav \
     --output-file extracted.txt
   ```

4. **Evaluasi Stego**

   ```bash
   python -m cli eval-stego \
     --original-wav cover.wav \
     --stego-wav stego.wav \
     --original-data secret.txt \
     --extracted-data extracted.txt \
     --plot
   ```

5. **Evaluasi Kripto**

   ```bash
   python -m cli eval-crypto \
     --curve secp256r1 \
     --data-size 1024 \
     --trials 100
   ```

##  Detil Teknis

* **ECIES**: Generate ephemeral key ➔ ECDH ➔ HKDF-SHA256 ➔ AES-GCM encrypt ➔ paket `[R||nonce||ciphertext||tag]`
* **DWT Stego**: Dekomposisi audio ➔ modifikasi koefisien wavelet ➔ inverse DWT ➔ simpan stego.wav

##  Contoh Skrip

Lihat folder `examples/` untuk contoh:

* `generate_keys.py`
* `encrypt_and_embed.py`
* `extract_and_decrypt.py`

---

*Kelompok 3—ECC-AES GCM & DWT Audio Steganography*
