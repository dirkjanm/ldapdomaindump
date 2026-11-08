import datetime
import unittest

from ldapdomaindump import domainDumpConfig, reportWriter


class ReportWriterAgeTest(unittest.TestCase):
    def setUp(self):
        self.writer = reportWriter(domainDumpConfig())

    def test_ns_to_minutes_accepts_string_values(self):
        self.assertAlmostEqual(self.writer.nsToMinutes('-36288000000000'), 60480.0)

    def test_ns_to_days_accepts_string_values(self):
        self.assertAlmostEqual(self.writer.nsToDays('-36288000000000'), 42.0)

    def test_timedelta_values_still_work(self):
        delta = datetime.timedelta(days=42)
        self.assertAlmostEqual(self.writer.nsToDays(delta), 42.0)
        self.assertAlmostEqual(self.writer.nsToMinutes(delta), 60480.0)


if __name__ == '__main__':
    unittest.main()
