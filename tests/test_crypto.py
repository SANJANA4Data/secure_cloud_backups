import os
import unittest
from pathlib import Path

from cryptography.fernet import Fernet

from tests.test_helpers import TempConfig
from utils.crypto import decrypt_file, encrypt_file


class CryptoTests(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        with TempConfig() as data_dir:
            key = Fernet.generate_key()
            os.environ["SCB_ENCRYPTION_KEY"] = key.decode("utf-8")

            input_path = Path(data_dir) / "sample.txt"
            encrypted_path = Path(data_dir) / "sample.txt.enc"
            output_path = Path(data_dir) / "sample_out.txt"

            input_path.write_text("secure backup content", encoding="utf-8")
            encrypt_file(str(input_path), str(encrypted_path))
            decrypt_file(str(encrypted_path), str(output_path))

            self.assertEqual(input_path.read_text(encoding="utf-8"), output_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
