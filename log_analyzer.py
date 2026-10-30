#!/usr/bin/env python3
"""
Log File Analyzer
=================
Task 30: Level 1, Python Programming Track

A high-performance, standard-library-only log analysis tool designed to parse
and report metrics from Apache/Nginx Common Log Format (CLF) access logs.

Features:
- Regex-based log line parsing for Common Log Format entries.
- Streaming file processor capable of processing arbitrarily large logs efficiently.
- Aggregation of total requests, HTTP methods, status code classes, and error rates.
- Ranking of most frequent client IP addresses and most requested endpoints.
- Bandwidth tracking (total bytes, average response payload).
- Security anomaly detection (identifies IPs exhibiting excessive 4xx/5xx errors).
- Clean text summary generation and optional CSV export.
"""

import argparse
import csv
from collections import Counter
from dataclasses import dataclass
import os
import re
import sys
from typing import Dict, List, Optional, Tuple


# Regex pattern for Common Log Format (CLF):
# Format: IP - - [Timestamp] "METHOD /endpoint PROTOCOL" STATUS BYTES
# Example: 192.168.1.10 - - [30/Oct/2026:10:15:32 +0530] "GET /index.html HTTP/1.1" 200 1024
LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+'                  # Client IP address
    r'\S+\s+\S+\s+'                     # Remote logname & authenticated user (identd/auth)
    r'\[(?P<timestamp>[^\]]+)\]\s+'     # Request timestamp [DD/Mon/YYYY:HH:MM:SS +ZZZZ]
    r'"(?:'
        r'(?P<method>[A-Z]+)\s+'        # HTTP Method (GET, POST, etc.)
        r'(?P<endpoint>\S+)'            # Requested URI/endpoint
        r'(?:\s+(?P<protocol>[^"]+))?'  # HTTP Protocol (e.g. HTTP/1.1)
    r'|(?P<raw_request>[^"]*)'          # Fallback for non-standard / malformed requests
    r')"\s+'
    r'(?P<status>\d{3})\s+'             # HTTP 3-digit status code
    r'(?P<bytes>\d+|-)'                 # Response body bytes or '-'
)

# Standard HTTP status code descriptions for human-readable reports
HTTP_STATUS_NAMES: Dict[int, str] = {
    200: "OK",
    201: "Created",
    202: "Accepted",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}


@dataclass(frozen=True)
class LogRecord:
    """Represents a single parsed log line."""
    ip: str
    timestamp: str
    method: str
    endpoint: str
    protocol: str
    status: int
    byte_count: int


@dataclass
class LogAnalysis:
    """Aggregated metrics and statistical counters from log processing."""
    total_lines: int = 0
    parsed_lines: int = 0
    malformed_lines: int = 0
    total_bytes: int = 0
    
    # Aggregation counters
    ip_counter: Counter = None
    endpoint_counter: Counter = None
    method_counter: Counter = None
    status_counter: Counter = None
    status_class_counter: Counter = None
    
    # Error tracking
    error_counter: Counter = None
    ip_error_counter: Counter = None
    endpoint_error_counter: Counter = None
    
    # Bandwidth tracking per IP
    ip_bytes_counter: Counter = None

    def __post_init__(self):
        if self.ip_counter is None:
            self.ip_counter = Counter()
        if self.endpoint_counter is None:
            self.endpoint_counter = Counter()
        if self.method_counter is None:
            self.method_counter = Counter()
        if self.status_counter is None:
            self.status_counter = Counter()
        if self.status_class_counter is None:
            self.status_class_counter = Counter()
        if self.error_counter is None:
            self.error_counter = Counter()
        if self.ip_error_counter is None:
            self.ip_error_counter = Counter()
        if self.endpoint_error_counter is None:
            self.endpoint_error_counter = Counter()
        if self.ip_bytes_counter is None:
            self.ip_bytes_counter = Counter()

    @property
    def total_errors(self) -> int:
        """Returns total count of 4xx and 5xx responses."""
        return sum(self.error_counter.values())

    @property
    def error_rate(self) -> float:
        """Returns error responses as a percentage of total valid requests."""
        if self.parsed_lines == 0:
            return 0.0
        return (self.total_errors / self.parsed_lines) * 100.0

    @property
    def average_bytes(self) -> float:
        """Returns average payload size in bytes."""
        if self.parsed_lines == 0:
            return 0.0
        return self.total_bytes / self.parsed_lines


def parse_log_line(line: str) -> Optional[LogRecord]:
    """
    Parses a single line of Common Log Format using regex.
    
    Returns a LogRecord instance if valid, or None if the line does not match.
    """
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    data = match.groupdict()
    
    # Handle optional bytes field ('-' means 0 bytes transferred)
    raw_bytes = data.get("bytes", "0")
    byte_count = int(raw_bytes) if raw_bytes != "-" else 0
    
    # Normalize method and endpoint
    method = data.get("method") or "UNKNOWN"
    endpoint = data.get("endpoint") or (data.get("raw_request") or "-").split()[0]
    protocol = data.get("protocol") or "-"
    status = int(data.get("status", 0))

    return LogRecord(
        ip=data["ip"],
        timestamp=data["timestamp"],
        method=method,
        endpoint=endpoint,
        protocol=protocol,
        status=status,
        byte_count=byte_count
    )


def analyze_log_file(filepath: str) -> LogAnalysis:
    """
    Reads and analyzes a server log file in a single streaming pass.
    
    Args:
        filepath: Path to the log file to read.
        
    Returns:
        LogAnalysis instance with populated counters and metrics.
        
    Raises:
        FileNotFoundError: If the specified log file does not exist.
        PermissionError: If read permissions are lacking.
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Log file not found: {filepath}")

    analysis = LogAnalysis()

    with open(filepath, mode="r", encoding="utf-8", errors="replace") as file:
        for line in file:
            line_str = line.strip()
            if not line_str:
                continue

            analysis.total_lines += 1
            record = parse_log_line(line_str)

            if record is None:
                analysis.malformed_lines += 1
                continue

            analysis.parsed_lines += 1
            analysis.total_bytes += record.byte_count

            # Aggregations
            analysis.ip_counter[record.ip] += 1
            analysis.endpoint_counter[record.endpoint] += 1
            analysis.method_counter[record.method] += 1
            analysis.status_counter[record.status] += 1
            analysis.ip_bytes_counter[record.ip] += record.byte_count

            # Status classification (2xx, 3xx, 4xx, 5xx)
            status_class = f"{record.status // 100}xx"
            analysis.status_class_counter[status_class] += 1

            # Error tracking (4xx client error, 5xx server error)
            if record.status >= 400:
                analysis.error_counter[record.status] += 1
                analysis.ip_error_counter[record.ip] += 1
                analysis.endpoint_error_counter[record.endpoint] += 1

    return analysis


def format_bytes(num_bytes: float) -> str:
    """Formats byte counts into human-readable strings (B, KB, MB, GB)."""
    units = ["B", "KB", "MB", "GB", "TB"]
    unit_index = 0
    val = float(num_bytes)
    while val >= 1024.0 and unit_index < len(units) - 1:
        val /= 1024.0
        unit_index += 1
    return f"{val:,.2f} {units[unit_index]}"


def generate_report(analysis: LogAnalysis, top_n: int = 5, source_file: str = "") -> str:
    """
    Generates a structured, professional text summary report of the log metrics.
    
    Args:
        analysis: LogAnalysis object containing aggregated data.
        top_n: Number of top items to display in rankings.
        source_file: Display name of the analyzed log file.
        
    Returns:
        Formatted multi-line report string.
    """
    lines: List[str] = []
    divider = "=" * 76
    sub_divider = "-" * 76

    lines.append(divider)
    lines.append("                  LOG FILE ANALYZER - SUMMARY REPORT                  ")
    lines.append(divider)
    lines.append(f" Source File Analyzed    : {os.path.basename(source_file) if source_file else 'N/A'}")
    lines.append(f" Total Log Lines Read    : {analysis.total_lines:,}")
    lines.append(f" Valid Requests Parsed   : {analysis.parsed_lines:,}")
    lines.append(f" Malformed / Skipped     : {analysis.malformed_lines:,}")
    lines.append(f" Overall Error Rate      : {analysis.error_rate:.2f}% ({analysis.total_errors:,} error responses)")
    lines.append(f" Total Bandwidth Served  : {format_bytes(analysis.total_bytes)} ({analysis.total_bytes:,} bytes)")
    lines.append(f" Average Response Size   : {format_bytes(analysis.average_bytes)}")
    lines.append(divider)
    lines.append("")

    # 1. HTTP Methods Distribution
    lines.append("1. HTTP REQUEST METHODS")
    lines.append(sub_divider)
    lines.append(f"{'Method':<12} {'Count':<12} {'Percentage':<15} {'Distribution'}")
    lines.append(sub_divider)
    for method, count in analysis.method_counter.most_common():
        pct = (count / analysis.parsed_lines * 100.0) if analysis.parsed_lines > 0 else 0.0
        bar = "#" * int(pct / 4)
        lines.append(f"{method:<12} {count:<12,} {pct:>6.2f}%        {bar}")
    lines.append("")

    # 2. HTTP Status Codes & Status Classes
    lines.append("2. HTTP STATUS CODE DISTRIBUTION")
    lines.append(sub_divider)
    lines.append("Status Class Summary:")
    class_labels = {
        "2xx": "2xx Success",
        "3xx": "3xx Redirection",
        "4xx": "4xx Client Error",
        "5xx": "5xx Server Error"
    }
    for s_class in sorted(analysis.status_class_counter.keys()):
        c_count = analysis.status_class_counter[s_class]
        c_pct = (c_count / analysis.parsed_lines * 100.0) if analysis.parsed_lines > 0 else 0.0
        label = class_labels.get(s_class, f"{s_class} Unknown")
        lines.append(f"  - {label:<22} : {c_count:>5,} requests ({c_pct:>5.1f}%)")
    
    lines.append("")
    lines.append(f"{'Status Code':<14} {'Description':<26} {'Count':<10} {'Percentage'}")
    lines.append(sub_divider)
    for status, count in sorted(analysis.status_counter.items(), key=lambda item: (-item[1], item[0])):
        desc = HTTP_STATUS_NAMES.get(status, "Unknown")
        pct = (count / analysis.parsed_lines * 100.0) if analysis.parsed_lines > 0 else 0.0
        lines.append(f"{status:<14} {desc:<26} {count:<10,} {pct:>6.2f}%")
    lines.append("")

    # 3. Error Responses Breakdown
    lines.append("3. ERROR RESPONSES BREAKDOWN (4xx & 5xx)")
    lines.append(sub_divider)
    if analysis.total_errors == 0:
        lines.append(" No 4xx or 5xx errors recorded. All requests succeeded!")
    else:
        client_errs = sum(c for s, c in analysis.status_counter.items() if 400 <= s < 500)
        server_errs = sum(c for s, c in analysis.status_counter.items() if 500 <= s < 600)
        lines.append(f" Client Errors (4xx)     : {client_errs:,} ({client_errs/analysis.parsed_lines*100:.1f}%)")
        lines.append(f" Server Errors (5xx)     : {server_errs:,} ({server_errs/analysis.parsed_lines*100:.1f}%)")
        lines.append("")
        lines.append("Top Endpoints Generating Errors:")
        for endpoint, err_count in analysis.endpoint_error_counter.most_common(top_n):
            lines.append(f"  - {endpoint:<30} : {err_count:>4,} failed requests")
    lines.append("")

    # 4. Most Frequent IP Addresses
    lines.append(f"4. TOP {top_n} MOST FREQUENT CLIENT IP ADDRESSES")
    lines.append(sub_divider)
    lines.append(f"{'Rank':<6} {'IP Address':<18} {'Requests':<12} {'Traffic %':<12} {'Bandwidth'}")
    lines.append(sub_divider)
    for rank, (ip, count) in enumerate(analysis.ip_counter.most_common(top_n), start=1):
        pct = (count / analysis.parsed_lines * 100.0) if analysis.parsed_lines > 0 else 0.0
        ip_bytes = analysis.ip_bytes_counter.get(ip, 0)
        lines.append(f"#{rank:<5} {ip:<18} {count:<12,} {pct:>6.2f}%     {format_bytes(ip_bytes):<12}")
    lines.append("")

    # 5. Most Requested Endpoints
    lines.append(f"5. TOP {top_n} MOST REQUESTED ENDPOINTS")
    lines.append(sub_divider)
    lines.append(f"{'Rank':<6} {'Endpoint':<34} {'Requests':<12} {'Percentage'}")
    lines.append(sub_divider)
    for rank, (endpoint, count) in enumerate(analysis.endpoint_counter.most_common(top_n), start=1):
        pct = (count / analysis.parsed_lines * 100.0) if analysis.parsed_lines > 0 else 0.0
        lines.append(f"#{rank:<5} {endpoint:<34} {count:<12,} {pct:>6.2f}%")
    lines.append("")

    # 6. Security & Anomaly Insights
    lines.append("6. SECURITY & ANOMALY OBSERVATIONS")
    lines.append(sub_divider)
    suspicious_ips: List[Tuple[str, int, float]] = []
    for ip, err_count in analysis.ip_error_counter.items():
        total_ip_reqs = analysis.ip_counter[ip]
        err_pct = (err_count / total_ip_reqs) * 100.0
        # Flag if IP sent at least 3 errors and had >= 50% error rate
        if err_count >= 3 and err_pct >= 50.0:
            suspicious_ips.append((ip, err_count, err_pct))

    if suspicious_ips:
        lines.append(" [!] Suspicious Client Activity Detected:")
        for s_ip, s_errs, s_rate in sorted(suspicious_ips, key=lambda x: -x[1]):
            lines.append(
                f"     * IP {s_ip}: {s_errs}/{analysis.ip_counter[s_ip]} requests failed "
                f"({s_rate:.1f}% failure rate) -> Potential scanner/brute-force activity."
            )
    else:
        lines.append(" [i] No high-frequency error anomalies detected across clients.")

    # High frequency 404 endpoints
    not_founds = [ep for ep, count in analysis.endpoint_error_counter.items() 
                  if any(parse_log_line(f"{ep}").status == 404 for _ in [0] if False)]
    lines.append(divider)
    lines.append("                     END OF SUMMARY REPORT                            ")
    lines.append(divider)

    return "\n".join(lines)


def export_csv_summary(analysis: LogAnalysis, output_csv_path: str) -> None:
    """
    Exports structured summary metrics into a clean CSV file using standard library csv.
    
    Includes sections for Top IPs and Top Endpoints.
    """
    with open(output_csv_path, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        
        # General Overview
        writer.writerow(["Section", "Metric", "Value"])
        writer.writerow(["Overview", "Total Requests", analysis.parsed_lines])
        writer.writerow(["Overview", "Total Errors", analysis.total_errors])
        writer.writerow(["Overview", "Error Rate (%)", f"{analysis.error_rate:.2f}"])
        writer.writerow(["Overview", "Total Bytes", analysis.total_bytes])
        writer.writerow([])
        
        # Top IP Addresses
        writer.writerow(["Rank", "IP Address", "Request Count", "Percentage", "Bytes Sent", "Errors"])
        for rank, (ip, count) in enumerate(analysis.ip_counter.most_common(), start=1):
            pct = f"{(count / analysis.parsed_lines * 100.0):.2f}%" if analysis.parsed_lines else "0.0%"
            b = analysis.ip_bytes_counter.get(ip, 0)
            errs = analysis.ip_error_counter.get(ip, 0)
            writer.writerow([rank, ip, count, pct, b, errs])
        writer.writerow([])
        
        # Top Endpoints
        writer.writerow(["Rank", "Endpoint", "Request Count", "Percentage", "Error Count"])
        for rank, (endpoint, count) in enumerate(analysis.endpoint_counter.most_common(), start=1):
            pct = f"{(count / analysis.parsed_lines * 100.0):.2f}%" if analysis.parsed_lines else "0.0%"
            errs = analysis.endpoint_error_counter.get(endpoint, 0)
            writer.writerow([rank, endpoint, count, pct, errs])


def main():
    """Main CLI entry point for the Log File Analyzer."""
    parser = argparse.ArgumentParser(
        description="Task 30: Common Log Format (CLF) File Analyzer - Standard Library Only",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        default="sample_access.log",
        help="Path to the access log file to analyze."
    )
    parser.add_argument(
        "-o", "--output",
        default="summary_report.txt",
        help="Output text report destination file path."
    )
    parser.add_argument(
        "--csv",
        dest="csv_export",
        default=None,
        help="Optional path to export tabular metrics as a CSV file."
    )
    parser.add_argument(
        "-t", "--top",
        type=int,
        default=5,
        help="Number of top IPs and Endpoints to include in ranked lists."
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Run silently without printing report to console (file still written)."
    )

    args = parser.parse_args()

    # Determine log file path
    log_path = args.logfile
    if not os.path.isabs(log_path) and not os.path.exists(log_path):
        # Check relative to script directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        candidate = os.path.join(script_dir, log_path)
        if os.path.exists(candidate):
            log_path = candidate

    if not os.path.exists(log_path):
        sys.stderr.write(f"Error: Log file '{args.logfile}' not found.\n")
        sys.exit(1)

    try:
        # Perform log analysis
        analysis = analyze_log_file(log_path)
        
        # Generate summary text report
        report_text = generate_report(analysis, top_n=args.top, source_file=log_path)

        # Output to console if not quiet
        if not args.quiet:
            print(report_text)

        # Write to output text file
        output_path = args.output
        if not os.path.isabs(output_path):
            script_dir = os.path.dirname(os.path.abspath(__file__))
            output_path = os.path.join(script_dir, output_path)

        with open(output_path, mode="w", encoding="utf-8") as out_file:
            out_file.write(report_text + "\n")
        
        if not args.quiet:
            print(f"\n[+] Summary report successfully written to: {output_path}")

        # Optional CSV export
        if args.csv_export:
            csv_path = args.csv_export
            if not os.path.isabs(csv_path):
                script_dir = os.path.dirname(os.path.abspath(__file__))
                csv_path = os.path.join(script_dir, csv_path)
            export_csv_summary(analysis, csv_path)
            if not args.quiet:
                print(f"[+] Tabular data successfully exported to CSV: {csv_path}")

    except Exception as exc:
        sys.stderr.write(f"Execution Error: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
