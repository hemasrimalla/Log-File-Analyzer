"""
Unit tests for Log File Analyzer (Task 30).
Using Python standard library 'unittest' only.
"""

import os
import tempfile
import unittest
from log_analyzer import (
    parse_log_line,
    analyze_log_file,
    format_bytes,
    generate_report,
    export_csv_summary,
    LogAnalysis,
    LogRecord,
)


class TestLogAnalyzer(unittest.TestCase):
    """Test suite for CLF parsing and aggregation logic."""

    def test_parse_valid_log_line(self):
        sample = '192.168.1.10 - - [30/Oct/2026:10:15:32 +0530] "GET /index.html HTTP/1.1" 200 4520'
        record = parse_log_line(sample)
        self.assertIsNotNone(record)
        self.assertEqual(record.ip, "192.168.1.10")
        self.assertEqual(record.timestamp, "30/Oct/2026:10:15:32 +0530")
        self.assertEqual(record.method, "GET")
        self.assertEqual(record.endpoint, "/index.html")
        self.assertEqual(record.protocol, "HTTP/1.1")
        self.assertEqual(record.status, 200)
        self.assertEqual(record.byte_count, 4520)

    def test_parse_hyphen_bytes_and_status(self):
        sample = '10.0.0.1 - - [30/Oct/2026:10:16:00 +0530] "GET /styles.css HTTP/1.1" 304 -'
        record = parse_log_line(sample)
        self.assertIsNotNone(record)
        self.assertEqual(record.status, 304)
        self.assertEqual(record.byte_count, 0)

    def test_parse_malformed_lines(self):
        invalid_samples = [
            "This is just random text, not a log line.",
            "192.168.1.10 - - missing bracket timestamp",
            "",
            "127.0.0.1 - - [bad] GET without quotes 200 123",
        ]
        for line in invalid_samples:
            self.assertIsNone(parse_log_line(line))

    def test_format_bytes(self):
        self.assertEqual(format_bytes(500), "500.00 B")
        self.assertEqual(format_bytes(1024), "1.00 KB")
        self.assertEqual(format_bytes(1024 * 1024), "1.00 MB")
        self.assertEqual(format_bytes(1024 * 1024 * 1024 * 2.5), "2.50 GB")

    def test_analyze_log_file_with_temp_data(self):
        temp_log_content = (
            '192.168.1.10 - - [30/Oct/2026:10:00:00 +0530] "GET /api/users HTTP/1.1" 200 1000\n'
            '192.168.1.10 - - [30/Oct/2026:10:00:05 +0530] "POST /api/users HTTP/1.1" 201 500\n'
            '10.0.0.5 - - [30/Oct/2026:10:00:10 +0530] "GET /login HTTP/1.1" 401 200\n'
            '10.0.0.5 - - [30/Oct/2026:10:00:15 +0530] "POST /login HTTP/1.1" 403 250\n'
            '10.0.0.5 - - [30/Oct/2026:10:00:20 +0530] "GET /non-existent HTTP/1.1" 404 300\n'
            'corrupted line that should be skipped\n'
        )
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as temp_file:
            temp_file.write(temp_log_content)
            temp_file_path = temp_file.name

        try:
            analysis = analyze_log_file(temp_file_path)
            self.assertEqual(analysis.total_lines, 6)
            self.assertEqual(analysis.parsed_lines, 5)
            self.assertEqual(analysis.malformed_lines, 1)
            self.assertEqual(analysis.total_bytes, 2250)
            self.assertEqual(analysis.ip_counter["192.168.1.10"], 2)
            self.assertEqual(analysis.ip_counter["10.0.0.5"], 3)
            self.assertEqual(analysis.method_counter["GET"], 3)
            self.assertEqual(analysis.method_counter["POST"], 2)
            self.assertEqual(analysis.status_counter[200], 1)
            self.assertEqual(analysis.status_counter[201], 1)
            self.assertEqual(analysis.status_counter[401], 1)
            self.assertEqual(analysis.status_counter[403], 1)
            self.assertEqual(analysis.status_counter[404], 1)
            self.assertEqual(analysis.total_errors, 3)
            self.assertAlmostEqual(analysis.error_rate, 60.0)

            # Report generation check
            report = generate_report(analysis, top_n=3, source_file="temp.log")
            self.assertIn("LOG FILE ANALYZER - SUMMARY REPORT", report)
            self.assertIn("10.0.0.5", report)
            self.assertIn("/api/users", report)
            self.assertIn("Suspicious Client Activity Detected", report)
        finally:
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)

    def test_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            analyze_log_file("non_existent_file_xyz_123.log")

    def test_csv_export(self):
        analysis = LogAnalysis()
        analysis.parsed_lines = 10
        analysis.total_bytes = 5000
        analysis.ip_counter["192.168.1.1"] = 10
        analysis.endpoint_counter["/home"] = 10

        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".csv") as temp_csv:
            csv_path = temp_csv.name

        try:
            export_csv_summary(analysis, csv_path)
            self.assertTrue(os.path.exists(csv_path))
            with open(csv_path, "r", encoding="utf-8") as f:
                content = f.read()
                self.assertIn("192.168.1.1", content)
                self.assertIn("/home", content)
                self.assertIn("Total Requests,10", content)
        finally:
            if os.path.exists(csv_path):
                os.remove(csv_path)


if __name__ == "__main__":
    unittest.main()
