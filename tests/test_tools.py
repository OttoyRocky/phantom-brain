"""
PHANTOM BRAIN - Tests de parsers y classifier
Usa fixtures reales del proyecto.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from tools.classifier import clasificar


class TestClassifier(unittest.TestCase):

    def test_pcap_por_extension(self):
        self.assertEqual(clasificar("sniffpmkid_0.pcap"), "WPA2")

    def test_nfc_por_extension(self):
        self.assertEqual(clasificar("Lemon.nfc"), "NFC")

    def test_log_marauder(self):
        self.assertEqual(clasificar("scanap_0.log"), "WiFi-Marauder")

    def test_texto_proxmark_em410x(self):
        self.assertEqual(clasificar("EM 410x ID 0A00244697"), "Proxmark3")

    def test_texto_proxmark_mifare(self):
        self.assertEqual(clasificar("MIFARE Classic 1K UID: 11 22 33 44"), "Proxmark3")

    def test_texto_wpa2(self):
        self.assertEqual(clasificar("EAPOL handshake capturado BSSID: AA:BB:CC:DD:EE:FF"), "WPA2")

    def test_texto_subghz(self):
        self.assertEqual(clasificar("Filetype: Flipper Radio Signal Frequency: 433920000"), "Sub-GHz")

    def test_texto_generico(self):
        self.assertEqual(clasificar("hola mundo sin contexto"), "Generico")


class TestProxmarkTool(unittest.TestCase):

    def test_em410x(self):
        from tools.proxmark_tool import ProxmarkTool
        t = ProxmarkTool()
        result = t.run("EM 410x ID 0A00244697\nChipset... T55x7")
        self.assertTrue(result.success)
        self.assertEqual(result.metadata["tipo"], "EM410x")

    def test_input_vacio(self):
        from tools.proxmark_tool import ProxmarkTool
        t = ProxmarkTool()
        self.assertFalse(t.validate(""))
        self.assertFalse(t.validate("   "))

    def test_mifare_classic(self):
        from tools.proxmark_tool import ProxmarkTool
        t = ProxmarkTool()
        result = t.run("MIFARE Classic 1K\nUID: 11 22 33 44\nSAK: 08")
        self.assertTrue(result.success)
        self.assertEqual(result.metadata["tipo"], "MIFARE Classic")


class TestNFCTool(unittest.TestCase):

    def test_fixture_lemon(self):
        from tools.nfc_tool import NFCTool
        t = NFCTool()
        if os.path.exists("Lemon.nfc"):
            result = t.run("Lemon.nfc")
            self.assertTrue(result.success)
        else:
            self.skipTest("Lemon.nfc no disponible")


class TestWPA2Tool(unittest.TestCase):

    def test_fixture_pcap(self):
        from tools.wpa2_tool import WPA2Tool
        t = WPA2Tool()
        pcap = "sniffpmkid_0.pcap"
        if os.path.exists(pcap):
            result = t.run(pcap)
            self.assertTrue(result.success)
            self.assertIn("bssid", result.metadata)
        else:
            self.skipTest(f"{pcap} no disponible")

    def test_validate_archivo_inexistente(self):
        from tools.wpa2_tool import WPA2Tool
        t = WPA2Tool()
        self.assertFalse(t.validate("no_existe.pcap"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
