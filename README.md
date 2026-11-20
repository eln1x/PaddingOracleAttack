# Padding Oracle Attack - Vulnerable Server

A multithreaded demonstration server implementing an intentionally vulnerable AES-CBC encryption implementation to showcase **Padding Oracle attacks**. This educational project illustrates how improper error handling in cryptographic padding validation can leak information about plaintext content.

> ⚠️ **Warning**: This is a deliberately vulnerable implementation for educational and authorized testing purposes only. Never use this in production or on systems you do not own or have explicit permission to test.

## About Padding Oracle Attacks

A **Padding Oracle attack** is a cryptanalysis technique that exploits how a server responds to incorrectly padded ciphertexts. By analyzing whether the server returns different error messages for valid vs. invalid padding, an attacker can:

- Decrypt messages without knowing the encryption key
- Forge new valid ciphertexts
- Ultimately recover plaintext from encrypted data

The vulnerability exists because this server distinguishes between:
- Invalid padding errors
- Valid decryption with proper padding

An attacker can use this oracle (the server's response) to systematically decrypt messages byte-by-byte.

## Architecture

```
ThreadedServer
├── listen()           - Accepts incoming connections
├── listenToClient()   - Handles individual client requests
├── decrypt()          - Decrypts ciphertext using AES-CBC
├── ispkcs7()          - Validates PKCS7 padding (vulnerable!)
├── encrypt()          - Encrypts plaintext (unused in demo)
└── pkcs7()            - Applies PKCS7 padding
```

## Setup

### Prerequisites
- Python 2.7+ or Python 3.x
- PyCryptodome library

### Installation

```bash
# Install required dependencies
pip install pycryptodome

# Clone the repository
git clone https://github.com/eln1x/PaddingOracleAttack.git
cd PaddingOracleAttack
```

## Usage

### Starting the Vulnerable Server

```bash
python server.py
```

The server will start listening on `localhost:10000`:
```
Starting Padding Oracle attack - Vulnerable Server
```

### Interacting with the Server

Connect to the server and send a decryption request using the protocol:

```
Decrypt:<hex_ciphertext>
```

#### Example

```bash
# Using netcat
echo "Decrypt:748bffd64578632dd524d4c8d3788ef3" | nc localhost 10000
```

Expected response:
```
Plain-text message is: Hello Crypto!
Goodbye!
```

#### Invalid Padding Response

If the ciphertext decrypts to invalid padding:
```
Server ERROR, Goodbye
```

This response leaks information about the padding validity!

## Implementation Details

### Encryption Parameters
- **Algorithm**: AES-128 in CBC mode
- **Secret Key**: `6374633270776e21` (hex)
- **IV**: `7669683478307273` (hex)
- **Padding**: PKCS7

### Vulnerable Code

The vulnerability is in the `ispkcs7()` method:

```python
def ispkcs7(self, plaintext):
    l = len(plaintext)
    c = ord(plaintext[l-1])
    if (c > 16) or (c < 1):
        return "INTERNAL SERVER ERROR"  # Different error message!
    if plaintext[l-c:] != chr(c)*c:
        return "INTERNAL SERVER ERROR"  # Different error message!
    return plaintext
```

**The Problem**: The server returns distinct error messages for padding validation failures vs. successful decryption. This allows attackers to distinguish valid padding from invalid padding, enabling the oracle attack.

## Attack Demonstration

A padding oracle attack typically proceeds as follows:

1. **Capture** an encrypted message
2. **Modify** the ciphertext byte-by-byte
3. **Send** each modified version to the server
4. **Analyze** the server responses:
   - If padding is valid → valid decryption occurred
   - If padding is invalid → returns error
5. **Deduce** the last byte of plaintext from padding behavior
6. **Repeat** for each byte of the plaintext block
7. **Recover** the entire plaintext

## Security Lessons

This implementation demonstrates why:

1. ✗ **Don't leak padding errors** - Different error messages for padding vs. decryption failures
2. ✗ **Don't use CBC mode naively** - Easily vulnerable to padding oracle attacks
3. ✓ **Use authenticated encryption** - Use AES-GCM, ChaCha20-Poly1305, or similar AEAD modes
4. ✓ **Return consistent errors** - Always return the same response regardless of failure reason
5. ✓ **Use established libraries** - Don't implement cryptography yourself

## Secure Alternatives

### Modern Encryption
```python
from Crypto.Cipher import AES
# Use AES-GCM instead of CBC
cipher = AES.new(key, AES.MODE_GCM)
```

### Python Libraries
- **cryptography**: Well-tested, actively maintained
- **NaCl/libsodium**: High-level, hard to misuse

## Testing & Ethical Use

This project is intended for:
- 🎓 Educational purposes and learning
- 🔬 Authorized security research and testing
- 🧪 Proof-of-concept demonstrations in controlled environments

**Authorized use only**: Only test on systems you own or have explicit written permission to test.

## References

- [CWE-209: Information Exposure Through an Error Message](https://cwe.mitre.org/data/definitions/209.html)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [OWASP: Padding Oracle](https://owasp.org/www-community/attacks/Padding_Oracle)
- [The Padding Oracle Attack (Academic)](https://en.wikipedia.org/wiki/Padding_oracle_attack)

## Author

**Ahmad Mahfouz** (@eln1x)

## License

This project is provided as-is for educational and authorized testing purposes.

---

**Disclaimer**: Use only in controlled environments with proper authorization. Unauthorized testing of computer systems is illegal.

