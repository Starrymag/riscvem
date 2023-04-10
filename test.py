import unittest
from emulator import cpu


class test_sign_extend(unittest.TestCase):
    def test_negative(self):
        self.assertEqual(cpu.sign_extend(0b1111_1111, 8), -1)
        self.assertEqual(cpu.sign_extend(0b1000_0001, 8), -127)
        self.assertEqual(cpu.sign_extend(0b1011, 4), -5)

    def test_positive(self):
        self.assertEqual(cpu.sign_extend(0b0000_0000, 8), 0)
        self.assertEqual(cpu.sign_extend(0b0111_1111, 8), 127)
        self.assertEqual(cpu.sign_extend(0b01011, 5), 11)
        self.assertEqual(cpu.sign_extend(0b01, 2), 1)

    def test_faliure(self):
        with self.assertRaises(TypeError):
            cpu.sign_extend("3", 4)
        with self.assertRaises(TypeError):
            cpu.sign_extend("3", "sss")
        with self.assertRaises(TypeError):
            cpu.sign_extend(0b1111, "0x234")


if __name__ == "__main__":
    unittest.main()
