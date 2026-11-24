import unittest
from pathlib import Path
from audit import audit

class AuditTest(unittest.TestCase):
    def setUp(self):
        self.good = Path('sample_running_config.txt').read_text()
    def status(self, config, number):
        return audit(config)['results'][number-1]['status']
    def test_good(self):
        self.assertEqual(audit(self.good)['passed'],20)
    def test_telnet(self):
        self.assertEqual(self.status(self.good.replace('transport input ssh','transport input ssh telnet',1),8),'FAIL')
    def test_missing_acl(self):
        self.assertEqual(self.status(self.good.replace('access-class MGMT-ACL in','access-class UNKNOWN in',1),10),'FAIL')
    def test_timeout(self):
        self.assertEqual(self.status(self.good.replace('exec-timeout 5 0','exec-timeout 0 0',1),17),'FAIL')
    def test_outside(self):
        self.assertEqual(self.status(self.good.replace('no cdp run','cdp run'),6),'FAIL')
    def test_before(self):
        self.assertLess(audit(Path('before_config.txt').read_text())['passed'],20)
