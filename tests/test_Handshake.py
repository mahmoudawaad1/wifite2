import sys
sys.path.insert(0, '..')

from wifite.model.handshake import Handshake
from wifite.util.process import Process

import unittest
import os
import inspect

class TestHandshake(unittest.TestCase):
    ''' Test suite for Handshake parsing and generation '''

    def getFile(self, filename):
        ''' Helper method to get full path to .cap file '''
        this_file = os.path.abspath(inspect.getsourcefile(self.getFile))
        this_dir = os.path.dirname(this_file)
        return os.path.join(this_dir, 'files', filename)

    def testAnalyze(self):
        ''' Test if Handshake.analyze() runs without error '''
        hs_file = self.getFile('handshake_exists.cap')
        hs = Handshake(hs_file, bssid='A4:2B:8C:16:6B:3A')
        try:
            hs.analyze()
        except Exception as e:
            self.fail(f"analyze() raised an exception unexpectedly: {e}")

    @unittest.skipUnless(Process.exists('tshark'), 'tshark is missing')
    def testHandshakeTshark(self):
        ''' Test handshake detection using tshark '''
        hs_file = self.getFile('handshake_exists.cap')
        hs = Handshake(hs_file, bssid='A4:2B:8C:16:6B:3A')
        self.assertGreater(len(hs.tshark_handshakes()), 0)

    @unittest.skipUnless(Process.exists('pyrit'), 'pyrit is missing')
    def testHandshakePyrit(self):
        ''' Test handshake detection using pyrit '''
        hs_file = self.getFile('handshake_exists.cap')
        hs = Handshake(hs_file, bssid='A4:2B:8C:16:6B:3A')
        self.assertGreater(len(hs.pyrit_handshakes()), 0)

    @unittest.skipUnless(Process.exists('cowpatty'), 'cowpatty is missing')
    def testHandshakeCowpatty(self):
        ''' Test handshake detection using cowpatty '''
        hs_file = self.getFile('handshake_exists.cap')
        hs = Handshake(hs_file, bssid='A4:2B:8C:16:6B:3A')
        hs.divine_bssid_and_essid()
        self.assertGreater(len(hs.cowpatty_handshakes()), 0)

    @unittest.skipUnless(Process.exists('aircrack-ng'), 'aircrack-ng is missing')
    def testHandshakeAircrack(self):
        ''' Test handshake detection using aircrack-ng '''
        hs_file = self.getFile('handshake_exists.cap')
        hs = Handshake(hs_file, bssid='A4:2B:8C:16:6B:3A')
        self.assertGreater(len(hs.aircrack_handshakes()), 0)


if __name__ == '__main__':
    unittest.main()
