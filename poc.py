from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac
import os
import struct

GLOBAL_SECRETS = {
    "subupdate_salt": os.urandom(16),   # 128-bit salt
    "hmac_key": os.urandom(32)          # Shared MAC key for verifying authenticity
}

# Make subupdate key: hash(decoder_id + salt)
def make_subupdate_key(decoder_id: int):
    prehash = decoder_id.to_bytes() + GLOBAL_SECRETS["subupdate_salt"]
    
    # Using BLAKE2s for hashing
    hasher = hashes.Hash(hashes.BLAKE2s())
    
    hasher.update(prehash)

    return hasher.finalize()

class Decoder:
    def __init__(self, id):
        self.id = id

class Encoder:
    def __init__(self):
        pass

    def generate_subscription_update(self, decoder_id: int, channel_id: int):

        # We encrypt the subscription update data with this
        subupdate_key = make_subupdate_key(decoder_id)

        # Generate subcription update body
        # Channel id, start timestamp, end timestamp, channel key
        body = struct.pack(">BQQ", channel_id, 0, 1000, b"some random channel key")


        # Encrypt body using AES-CBC
        # We don't use AES-GCM because the encryption + authentication uses the same key, this is not a safe practice.
        # We will AES-CBC + HMAC separately 
        iv = os.urandom(16) # Initialization vector introduces randomness

        aes_cipher = Cipher(algorithms.AES(subupdate_key), modes.CBC(iv))

        # Pad to make data multiple of 16 bytes (block size)
        padder = padding.PKCS7(128).padder()
        padded_body = padder.update(body) + padder.finalize()

        # Encrypt padded data
        encryptor = aes_cipher.encryptor()
        encrypted_body = encryptor.update(padded_body) + encryptor.finalize()

        # Compute HMAC and prepend to body
        h = hmac.HMAC(GLOBAL_SECRETS["hmac_key"], hashes.BLAKE2s())


        # Generate subscription update packet header
        # Magic byte '%', OPCODE 'S', body length
        header = struct.pack(">BBH", '%', 'S', len(body))



# # Decrypt the data to verify
# decryptor = cipher.decryptor()
# decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

# # Remove padding after decryption
# unpadder = padding.PKCS7(128).unpadder()
# unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()


def main():
    tv_station = Encoder()

    decoder = Decoder(0xDEADBEEF)

    tv_station.generate_subscription_update(decoder.id, channel_id=1)


if __name__ == "__main__":
    main()

