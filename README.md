# Bitcoin Wallet Generator 💰🔑

## Description 📝
This project implements a Bitcoin wallet generator using mnemonic phrases, private and public keys. The program generates random mnemonic phrases, then uses them to create private and public keys, along with the corresponding Bitcoin address.

All generated data (mnemonic, seed phrase, private key, public key, and Bitcoin address) are written to the `wallets.txt` file 📄.

## Features ⚡
- Generate random mnemonic phrases for Bitcoin 🧠.
- Generate private and public keys 🔐 based on the mnemonic phrases.
- Generate the corresponding Bitcoin address 💳.
- Write all generated data to a text file 💾.

## Installation 🚀

To use this project, you need:
- A C++ compiler (e.g., `g++`) 💻.
- OpenSSL libraries for cryptography 🔒.

### 1. Installing OpenSSL (if not installed)

**For Ubuntu/Debian**:
```bash
sudo apt update
sudo apt install libssl-dev
```

**For macOS** (using Homebrew):
```bash
brew install openssl
```

### 2. Compiling the Program ⚙️
Once you've confirmed that OpenSSL is installed, compile the project with the following command:

```bash
g++ -o btc_wallet btc_wallet.cpp -lssl -lcrypto
```

### 3. Running the Program 🚀
To run the program, execute the following command:

```bash
./btc_wallet
```

### 4. `wallets.txt` File Format 📂
The program will write the generated data to the `wallets.txt` file. The data structure in the file will look like this:

```
<------------------------>
Mnemonic: example mnemonic phrase
Seed: 1234567890abcdef
SHA256 of Seed: abcdef1234567890
Private Key: abcdef1234567890
Public Key: abcdef1234567890
Bitcoin Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
<------------------------>
```

Each set of generated data will be written to the file sequentially 🔄.

## Notes ⚠️
- The program will run infinitely and generate new data with each run 🔁.
- To stop the program, use `Ctrl + C` 🚫.