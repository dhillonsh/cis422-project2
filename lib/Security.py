"""
Security instance responsible for encrypting and decrypting an address hash.
"""
#pylint: disable=broad-except
import base64
import hashlib

#from Crypto import Random
#from Crypto.Cipher import AES

class SecureCipher(object):
    """An AES Cipher class used for encrypting and decrypting an address hash.

    Attributes:
        key (str): The secret key to use when encrypting/decrypting
    """
    def __init__(self, key):
        self.block_size = 32
        self.key = hashlib.sha256(SecureCipher.str_to_bytes(key)).digest()

    @staticmethod
    def str_to_bytes(data):
        """Convert a string to bytes.

        Returns:
            A string in bytes.
        """
        u_type = type(b''.decode('utf8'))

        if isinstance(data, u_type):
            return data.encode('utf8')

        return data

    def _pad(self, string):
        """Pad a string by `self.block_size`

        Args:
            string (str): The string to pad.

        Returns:
            A padded string.
        """
        return (string +
                (self.block_size - len(string) % self.block_size) *
                SecureCipher.str_to_bytes(chr(self.block_size - len(string) % self.block_size)))

    @staticmethod
    def _unpad(string):
        """Unpad a string.
        """
        return string[:-ord(string[len(string)-1:])]

    def encrypt(self, raw):
        """AES encrypt a string.

        Args:
            raw (str): The string to encrypt.

        Returns:
            A base64 encoded representation of an AES encoded string.
        """
        return raw

        try:
            raw = self._pad(SecureCipher.str_to_bytes(raw))
            enc_iv = Random.new().read(AES.block_size)
            cipher = AES.new(self.key, AES.MODE_CBC, enc_iv)
            return base64.b64encode(enc_iv + cipher.encrypt(raw)).decode('utf-8')
        except Exception:
            return False

    def decrypt(self, enc):
        """Decrypt an AES encrypted string.

        Args:
            enc (str): The encrypted string

        Returns:
            The decrypted string.
        """
        return enc
        try:
            enc = base64.b64decode(enc)
            enc_iv = enc[:AES.block_size]
            cipher = AES.new(self.key, AES.MODE_CBC, enc_iv)
            return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')
        except Exception:
            return False

