from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac

import os
import struct

"""
Quick proof of concept to test the correctness of our design.
"""

GLOBAL_SECRETS = {
    "subupdate_salt": os.urandom(16),   # 128-bit salt
    "hmac_key": os.urandom(32)          # Shared MAC key for verifying authenticity
}

# Make subupdate key: hash(decoder_id + salt)
def make_subupdate_key(decoder_id: int):
    prehash = decoder_id.to_bytes(4, 'big') + GLOBAL_SECRETS["subupdate_salt"]
    
    # Using BLAKE2s for hashing
    hasher = hashes.Hash(hashes.BLAKE2s(32))
    
    hasher.update(prehash)

    return hasher.finalize()

class Decoder:
    def __init__(self, id):
        self.id = id
        self.subscription_channel_key = None

    # Verify that the message hasn't been tampered by comparing HMAC signatures
    def verify_hmac(self, old_hmac_sig: bytes, payload: bytes):
        h = hmac.HMAC(GLOBAL_SECRETS["hmac_key"], hashes.BLAKE2s(32))

        h.update(payload)
        h_copy = h.copy()
        h.finalize()

        h_copy.verify(old_hmac_sig)

        print("HMAC verified!")

    def decrypt_subcription_update(self, subscription_update_data: bytes):
        payload = subscription_update_data[52:]
        hmac_sig = subscription_update_data[4:36]
        iv = subscription_update_data[36:36 + 16]

        # Throws error if HMAC verification fails
        self.verify_hmac(hmac_sig, payload)

        # We use this to decrypt the packet
        subupdate_key = make_subupdate_key(self.id)

        aes_cipher = Cipher(algorithms.AES(subupdate_key), modes.CBC(iv))

        # Decrypt the data to verify
        decryptor = aes_cipher.decryptor()
        decrypted_data = decryptor.update(payload) + decryptor.finalize()

        # Remove padding after decryption
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        packet = struct.unpack(">BQQQQ", unpadded_data)
        channel_id = packet[0]
        start_ts = packet[1]
        end_ts = packet[2]
        # Combine the 2 8-byte ints into the channel key
        channel_key = packet[3] << 64 | packet[4]

        # We have the channel key, now we can start decoding frames
        self.subscription_channel_key = channel_key

        print("Received Subscription Update:")
        print("  Channel ID:", channel_id)
        print("  Start Time:", start_ts)
        print("  End Time:", end_ts)
        print("  Channel Key:", hex(channel_key))

    def decode_frame(self, frame: bytes):
        payload = frame[52:]
        hmac_sig = frame[4:36]
        iv = frame[36:36 + 16]

        self.verify_hmac(hmac_sig, payload)

        aes_cipher = Cipher(algorithms.AES(self.subscription_channel_key.to_bytes(16, 'big')), modes.CBC(iv))

        # Decrypt the data to verify
        decryptor = aes_cipher.decryptor()
        decrypted_data = decryptor.update(payload) + decryptor.finalize()

        # Remove padding after decryption
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        print("Received Frame:")
        print("  Frame Data:", unpadded_data)

class Encoder:
    def __init__(self):

        # Constant values for simplicity
        self.channel_keys = [
            0xababababababababababababababab00, # Channel 0 (emergency, doesnt need channel key)
            0xababababababababababababababab01, # Channel 1
            0xababababababababababababababab02, # Channel 2
        ]

    def generate_subscription_update(self, decoder_id: int, channel_id: int):

        # We encrypt the subscription update data with this
        subupdate_key = make_subupdate_key(decoder_id)

        # Generate subcription update body
        # Channel id, ex. start timestamp, ex. end timestamp, channel key
        body = struct.pack(">BQQ", channel_id, 0, 1000)
        body = body + self.channel_keys[channel_id].to_bytes(16, 'big')

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
        h = hmac.HMAC(GLOBAL_SECRETS["hmac_key"], hashes.BLAKE2s(32))

        h.update(encrypted_body)

        hmac_signature = h.finalize()

        # Generate subscription update packet header
        # Magic byte '%', OPCODE 'S', body length
        body_len = len(encrypted_body) + len(hmac_signature) + len(iv)
        header = struct.pack(">BBH", ord('%'), ord('S'), body_len)

        print("Encrypted Subscription Update:")
        print("  Header:")
        print("    Magic + Opcode:", header[0:2])
        print("    Body Length:", body_len)
        print("  Body:")
        print("    HMAC:", hmac_signature.hex(), f"(len {len(hmac_signature)})")
        print("    Payload:", encrypted_body.hex(), f"(len {len(encrypted_body)})")
        print("      IV:", iv.hex(), f"(len {len(iv)})")

        """
        Encrypted Packet: [Header][HMAC Signature + IV][Encrypted Payload]
        """
        return header + hmac_signature + iv + encrypted_body
    
    def generate_frame(self, channel_id: int):
        EXAMPLE_FRAME = b"...__..._lll____--....__"

        channel_key = self.channel_keys[channel_id]

        iv = os.urandom(16) # Initialization vector introduces randomness

        aes_cipher = Cipher(algorithms.AES(channel_key.to_bytes(16, 'big')), modes.CBC(iv))

        # Pad to make data multiple of 16 bytes (block size)
        padder = padding.PKCS7(128).padder()
        padded_body = padder.update(EXAMPLE_FRAME) + padder.finalize()

        # Encrypt padded data
        encryptor = aes_cipher.encryptor()
        encrypted_body = encryptor.update(padded_body) + encryptor.finalize()

        # Compute HMAC and prepend to body
        h = hmac.HMAC(GLOBAL_SECRETS["hmac_key"], hashes.BLAKE2s(32))

        h.update(encrypted_body)

        hmac_signature = h.finalize()

        body_len = len(encrypted_body) + len(hmac_signature) + len(iv)

        # Frame header with 'D' as opcode
        header = struct.pack(">BBH", ord('%'), ord('D'), body_len)

        print("Encrypted Frame:")
        print("  Header:")
        print("    Magic + Opcode:", header[0:2])
        print("    Body Length:", body_len)
        print("  Body:")
        print("    HMAC:", hmac_signature.hex(), f"(len {len(hmac_signature)})")
        print("    Payload:", encrypted_body.hex(), f"(len {len(encrypted_body)})")
        print("      IV:", iv.hex(), f"(len {len(iv)})")

        return header + hmac_signature + iv + encrypted_body


def main():
    encoder = Encoder()
    decoder = Decoder(id=0xDEADBEEF)

    subupdate_packet = encoder.generate_subscription_update(decoder.id, channel_id=1)

    print("\n")

    decoder.decrypt_subcription_update(subupdate_packet)

    print("\n")

    frame = encoder.generate_frame(channel_id=1)

    print("\n")

    decoder.decode_frame(frame)


if __name__ == "__main__":
    main()

