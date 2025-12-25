import unittest
import os
import gzip
import tempfile
import shutil
from unittest.mock import patch
from src.email_parser import EmailParser

class TestEmailParserDoS(unittest.TestCase):
    def setUp(self):
        self.parser = EmailParser()
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_gzip_limit(self):
        # Create a "large" gzip file
        # 1000 bytes > 50 bytes limit
        large_content = b"Subject: Test\n\n" + b"A" * 1000
        gz_path = os.path.join(self.test_dir, "test.eml.gz")

        with gzip.open(gz_path, "wb") as f:
            f.write(large_content)

        # Patch the MAX_EMAIL_SIZE inside email_parser module
        with patch('src.email_parser.MAX_EMAIL_SIZE', 50):
            data = self.parser.parse_email(gz_path)

        # Verify that raw_content is truncated to 50 bytes
        self.assertEqual(len(data["raw_content"]), 50)

    def test_file_limit(self):
        # Create a large plain file
        large_content = b"Subject: Test\n\n" + b"A" * 1000
        eml_path = os.path.join(self.test_dir, "test.eml")

        with open(eml_path, "wb") as f:
            f.write(large_content)

        with patch('src.email_parser.MAX_EMAIL_SIZE', 50):
            data = self.parser.parse_email(eml_path)

        # Verify that raw_content is truncated to 50 bytes
        self.assertEqual(len(data["raw_content"]), 50)

if __name__ == '__main__':
    unittest.main()
