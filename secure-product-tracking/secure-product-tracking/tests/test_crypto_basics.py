import unittest
from sptrack import crypto_basics as cb


class TestCaesar(unittest.TestCase):
    def test_roundtrip(self):
        msg = "SHIPMENT 42 LEFT WAREHOUSE"
        self.assertEqual(cb.caesar_decrypt(cb.caesar_encrypt(msg, 7), 7), msg)

    def test_known_value(self):
        self.assertEqual(cb.caesar_encrypt("ABC XYZ", 3), "DEF ABC")

    def test_crack_long_text(self):
        plain = ("THE PRODUCT LEFT THE MANUFACTURER AND WAS RECEIVED BY THE "
                 "DISTRIBUTOR BEFORE IT WAS SENT TO THE RETAILER")
        self.assertEqual(cb.caesar_crack(cb.caesar_encrypt(plain, 11)), 11)


class TestSubstitution(unittest.TestCase):
    def test_roundtrip(self):
        key = cb.random_substitution_key(seed=1)
        msg = "BATCH 17 RECEIVED AT DELHI HUB"
        self.assertEqual(cb.substitution_decrypt(cb.substitution_encrypt(msg, key), key), msg)

    def test_key_is_permutation(self):
        self.assertEqual(sorted(cb.random_substitution_key(5)), list(cb.ALPHABET))


class TestHash(unittest.TestCase):
    def test_sha256_known_vector(self):
        # FIPS 180-4 test vector for "abc"
        self.assertEqual(
            cb.sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_avalanche(self):
        bits = cb.avalanche_bits("product-001", "product-002")
        self.assertTrue(80 < bits < 176)   # roughly half of 256 bits flip


if __name__ == "__main__":
    unittest.main()
