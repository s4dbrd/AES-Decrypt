import hashlib
import itertools
import sys
from Crypto.Cipher import AES
from pwn import *
import time

BANNER = '''
****************************************************
*             AES Key Brute-Force Script           *
****************************************************
'''

SUCCESS_BANNER = '''
****************************************************
*              AES Key Found!                      *
****************************************************
'''

FAILURE_BANNER = '''
****************************************************
*              AES Key Not Found :(                *
****************************************************
'''

def brute_force_aes_key(iv, ciphertext, mac, verbose=False):
    # Generate all possible 16-byte AES keys
    keys = itertools.product(range(256), repeat=16)
    for key in keys:
        # Initialize AES cipher in CBC mode
        cipher = AES.new(bytes(key), AES.MODE_CBC, iv)
        # Decrypt the ciphertext using the current key
        plaintext = cipher.decrypt(ciphertext)
        # Verify the MAC of the decrypted plaintext
        if verify_mac(plaintext, mac):
            return key
        # Print the current key being tried if verbose mode is on
        if verbose:
            p2.status(str(key))

    # Key not found
    return None

def verify_mac(data, mac):
    # Calculate SHA-256 hash of the plaintext
    h = hashlib.sha256(data).digest()
    # Compare the hash with the given MAC
    return h == mac

if __name__ == '__main__':
    log.progress(BANNER)
    p1 = log.progress("AES Brute Force")
    p1.status("Starting bruteforce attack")
    time.sleep(2)
    p2 = log.progress("Key")
    # Example values
    iv = b'' # IV IN HEX FORMAT
    ciphertext = b'' # VALUE IN HEX FORMAT
    mac = b'' # MAC IN HEX FORMAT

    # Brute-force AES key
    key = brute_force_aes_key(iv, ciphertext, mac, verbose=True)
    if key is not None:
        log.success(SUCCESS_BANNER)
        print('Key found:', key)
    else:
        log.failure(FAILURE_BANNER)