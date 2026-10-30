# Log File Analyzer

> **Task 30: Build a Log File Analyzer**  
> **Track:** Python Programming Track (Level 1)  
> **Standard:** Python 3 Standard Library only (zero external dependencies)

A modular, high-performance command-line tool that parses, processes, and extracts actionable analytics from web server access logs formatted in the industry-standard **Apache / Nginx Common Log Format (CLF)**.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Project Structure](#project-structure)
- [Log Format Specification](#log-format-specification)
- [Key Features](#key-features)
- [Tools & Technologies](#tools--technologies)
- [Quick Start & Usage](#quick-start--usage)
  - [Basic Execution](#basic-execution)
  - [CLI Options & Arguments](#cli-options--arguments)
  - [Exporting Metrics to CSV](#exporting-metrics-to-csv)
  - [Running Unit Tests](#running-unit-tests)
- [Sample Summary Report](#sample-summary-report)
- [Architecture & Implementation Details](#architecture--implementation-details)
- [Core Python Concepts Applied](#core-python-concepts-applied)

---

## Project Overview

Web servers generate vast quantities of access logs every second. Analyzing these logs is fundamental for:
1. **Traffic Monitoring:** Understanding overall request volume, peak usage, and data transfer.
2. **Endpoint Optimization:** Discovering the most accessed routes and bottleneck endpoints.
3. **Reliability & Health:** Tracking 4xx (client errors) and 5xx (server errors) to pinpoint broken links or service failures.
4. **Security Analysis:** Detecting anomalous client behavior such as brute-force authentication attacks, automated vulnerability scanners, or unauthorized crawling.

This project implements a streaming, regex-powered log analyzer using **Python 3's built-in standard library**, producing both human-readable reports and machine-readable exports.

---

## Project Structure

```text
log-file-analyzer/
├── log_analyzer.py        # Main Python script with parser, aggregators, reporter, and CLI
├── sample_access.log      # Realistic sample access log (75 lines, 9 IPs, mixed statuses)
├── summary_report.txt     # Pre-generated output report from analyzing sample_access.log
├── test_log_analyzer.py   # Comprehensive unit tests using standard library 'unittest'
└── README.md              # Project documentation, guides, and architecture
```

---

## Log Format Specification

The tool parses the standard **Apache / Nginx Common Log Format (CLF)**:

```text
<Client-IP> <Identd> <Auth-User> [<Timestamp>] "<Method> <Endpoint> <Protocol>" <Status-Code> <Response-Bytes>
```

### Example Log Entry:
```text
192.168.1.10 - - [30/Oct/2026:10:15:32 +0530] "GET /index.html HTTP/1.1" 200 4520
```

### Fields Extracted:
| Field | Example Value | Description |
| :--- | :--- | :--- |
| **Client IP** | `192.168.1.10` | IPv4 or IPv6 client address |
| **Identd / Auth** | `- -` | Identity & authentication tokens (ignored if `-`) |
| **Timestamp** | `30/Oct/2026:10:15:32 +0530` | Request date, time, and timezone |
| **Method** | `GET` | HTTP verb (`GET`, `POST`, `PUT`, `DELETE`, etc.) |
| **Endpoint** | `/index.html` | Requested URI resource path |
| **Protocol** | `HTTP/1.1` | HTTP protocol version |
| **Status Code** | `200` | 3-digit HTTP response status |
| **Bytes** | `4520` | Body payload size in bytes (or `-` for 0 bytes) |

The included `sample_access.log` contains **75 realistic entries** with:
- **9 distinct IP addresses** with varied request distributions.
- **Realistic web endpoints:** `/index.html`, `/login`, `/api/users`, `/products`, `/about`, `/contact`, `/healthz`, `/checkout`.
- **Attack / scan attempts:** Repeated failed POST attempts to `/login`, probes to `/.env`, `/wp-login.php`, and `/admin`.
- **Diverse HTTP methods:** `GET`, `POST`, `PUT`, `DELETE`.
- **Full status spectrum:** `200`, `201`, `204`, `301`, `304`, `400`, `401`, `403`, `404`, `500`, `502`.

---

## Key Features

- **Streaming Line-by-Line File Processing:** Reads files iteratively without loading entire log files into memory, enabling analysis of multi-gigabyte files.
- **Robust Regular Expression Matching:** Compiles a named group regex (`re.compile`) that safely extracts log attributes while handling malformed lines and edge cases.
- **High-Performance Aggregations:** Uses `collections.Counter` and dictionaries to compute request counts, error rates, and traffic distributions in $O(N)$ time.
- **Detailed HTTP Status Classification:**
  - Grouped by class: `2xx` (Success), `3xx` (Redirection), `4xx` (Client Error), `5xx` (Server Error).
  - Individual breakdown of all observed HTTP status codes with official descriptions.
- **Bandwidth Metrics:** Computes total data transferred and average response payload, automatically scaled to B, KB, MB, or GB.
- **Security & Anomaly Detection:** Flags IP addresses exhibiting suspicious error rates (e.g., automated brute-force attacks or scanning bots).
- **Dual Output Modes:** Prints formatted, aligned tables to the console and writes `summary_report.txt`.
- **Optional CSV Export:** Exports structured data via Python's built-in `csv` module for spreadsheet or database ingestion.

---

## Tools & Technologies

This project strictly adheres to Level 1 constraints by using **only Python 3 standard library modules**:

- `collections.Counter`: High-efficiency tallies for IPs, endpoints, methods, and status codes.
- `re`: Compiled regular expressions with named groups for line parsing.
- `csv`: Structured comma-separated values export.
- `argparse`: Intuitive CLI with help flags and customizable arguments.
- `dataclasses`: Clean, strongly typed representation of log records and analytics.
- `unittest`: Automated unit test framework.

No external packages (`pip install`) are needed.

---

## Quick Start & Usage

### Basic Execution

Run the script directly. By default, it looks for `sample_access.log` in the local directory and writes `summary_report.txt`:

```bash
python log_analyzer.py
```

### CLI Options & Arguments

You can specify a custom log file, change output destinations, configure top-N limits, or silence console output:

```bash
python log_analyzer.py [LOGFILE] [-o OUTPUT] [--csv CSV_PATH] [-t TOP] [-q]
```

#### Parameters:
- `LOGFILE` (optional): Path to the access log file (defaults to `sample_access.log`).
- `-o`, `--output` (optional): Output text report destination (defaults to `summary_report.txt`).
- `--csv` (optional): Destination path for CSV metrics export.
- `-t`, `--top` (optional): Number of top IP addresses and endpoints to display (default: `5`).
- `-q`, `--quiet` (optional): Suppress terminal output (writes report directly to file).
- `-h`, `--help`: Display the CLI help manual.

#### Examples:

```bash
# Analyze a custom server log and save report to a specific file
python log_analyzer.py /var/log/nginx/access.log -o /reports/daily_report.txt

# Display top 10 most frequent items
python log_analyzer.py sample_access.log --top 10

# Generate text report and also export CSV metrics
python log_analyzer.py sample_access.log --csv log_metrics.csv
```

### Running Unit Tests

Run the included test suite to verify parsing logic, byte formatting, and metric aggregations:

```bash
python test_log_analyzer.py
```

Or via Python's test runner:

```bash
python -m unittest -v test_log_analyzer.py
```

---

## Sample Summary Report

Below is the report generated from `sample_access.log` (stored in `summary_report.txt`):

```text
============================================================================
                  LOG FILE ANALYZER - SUMMARY REPORT                  
============================================================================
 Source File Analyzed    : sample_access.log
 Total Log Lines Read    : 75
 Valid Requests Parsed   : 75
 Malformed / Skipped     : 0
 Overall Error Rate      : 25.33% (19 error responses)
 Total Bandwidth Served  : 208.29 KB (213,284 bytes)
 Average Response Size   : 2.78 KB
============================================================================

1. HTTP REQUEST METHODS
----------------------------------------------------------------------------
Method       Count        Percentage      Distribution
----------------------------------------------------------------------------
GET          56            74.67%        ##################
POST         16            21.33%        #####
PUT          2              2.67%        
DELETE       1              1.33%        

2. HTTP STATUS CODE DISTRIBUTION
----------------------------------------------------------------------------
Status Class Summary:
  - 2xx Success            :    53 requests ( 70.7%)
  - 3xx Redirection        :     3 requests (  4.0%)
  - 4xx Client Error       :    16 requests ( 21.3%)
  - 5xx Server Error       :     3 requests (  4.0%)

Status Code    Description                Count      Percentage
----------------------------------------------------------------------------
200            OK                         50          66.67%
403            Forbidden                  7            9.33%
401            Unauthorized               4            5.33%
404            Not Found                  4            5.33%
201            Created                    2            2.67%
304            Not Modified               2            2.67%
500            Internal Server Error      2            2.67%
204            No Content                 1            1.33%
301            Moved Permanently          1            1.33%
400            Bad Request                1            1.33%
502            Bad Gateway                1            1.33%

3. ERROR RESPONSES BREAKDOWN (4xx & 5xx)
----------------------------------------------------------------------------
 Client Errors (4xx)     : 16 (21.3%)
 Server Errors (5xx)     : 3 (4.0%)

Top Endpoints Generating Errors:
  - /login                         :   10 failed requests
  - /api/users                     :    2 failed requests
  - /admin                         :    1 failed requests
  - /wp-login.php                  :    1 failed requests
  - /api/feedback                  :    1 failed requests

4. TOP 5 MOST FREQUENT CLIENT IP ADDRESSES
----------------------------------------------------------------------------
Rank   IP Address         Requests     Traffic %    Bandwidth
----------------------------------------------------------------------------
#1     192.168.1.10       17            22.67%     71.08 KB    
#2     10.0.0.45          14            18.67%     8.81 KB     
#3     172.16.0.5         9             12.00%     14.15 KB    
#4     192.168.1.15       8             10.67%     41.90 KB    
#5     192.168.1.105      7              9.33%     12.69 KB    

5. TOP 5 MOST REQUESTED ENDPOINTS
----------------------------------------------------------------------------
Rank   Endpoint                           Requests     Percentage
----------------------------------------------------------------------------
#1     /api/users                         14            18.67%
#2     /index.html                        13            17.33%
#3     /login                             12            16.00%
#4     /products                          11            14.67%
#5     /healthz                           6              8.00%

6. SECURITY & ANOMALY OBSERVATIONS
----------------------------------------------------------------------------
 [!] Suspicious Client Activity Detected:
     * IP 10.0.0.45: 14/14 requests failed (100.0% failure rate) -> Potential scanner/brute-force activity.
============================================================================
                     END OF SUMMARY REPORT                            
============================================================================
```

---

## Architecture & Implementation Details

```text
┌──────────────────────┐
│  sample_access.log   │
└──────────┬───────────┘
           │ Streaming line-by-line read
           ▼
┌──────────────────────────────────────────────┐
│ parse_log_line(line)                         │
│ - Named-group Regex (LOG_PATTERN)            │
│ - Validates IP, Method, Route, Status, Bytes │
└──────────┬───────────────────────────────────┘
           │ Yields LogRecord
           ▼
┌──────────────────────────────────────────────┐
│ analyze_log_file(filepath)                   │
│ - collections.Counter aggregations           │
│ - Error & bandwidth metrics computation      │
│ - Returns LogAnalysis object                 │
└──────────┬───────────────────┬───────────────┘
           │                   │
           ▼                   ▼
┌────────────────────────┐  ┌────────────────────────┐
│ generate_report(...)   │  │ export_csv_summary(...)│
│ - Formatted Text Table │  │ - Tabular CSV Exporter │
│ - summary_report.txt   │  │ - log_metrics.csv      │
│ - Console stdout       │  │                        │
└────────────────────────┘  └────────────────────────┘
```

1. **`parse_log_line(line: str) -> Optional[LogRecord]`**:
   Uses a pre-compiled regular expression with named capture groups. It safely handles optional protocol identifiers, converts byte counts (substituting `0` when HTTP response body is `-`), and returns an immutable `LogRecord` dataclass instance.

2. **`analyze_log_file(filepath: str) -> LogAnalysis`**:
   Iterates through the file using a generator-like pattern without reading the whole file into RAM. It populates separate `Counter` instances for client IPs, endpoints, HTTP methods, status codes, and status code classes.

3. **`generate_report(analysis: LogAnalysis, top_n: int) -> str`**:
   Generates tabular, human-readable terminal and text outputs with fixed-width column formatting and visual ASCII distribution bars.

4. **`export_csv_summary(analysis: LogAnalysis, output_csv_path: str) -> None`**:
   Uses Python's `csv.writer` to write structured metric sections.

---

## Core Python Concepts Applied

1. **String Manipulation & Regex:**
   - Compiled patterns (`re.compile`) with named capture groups (`(?P<ip>\S+)`, `(?P<status>\d{3})`).
   - String formatting, padding, alignment (`{field:<18}`, `{pct:>6.2f}%`), and ASCII progress bars.
2. **Dictionaries & Collections:**
   - `collections.Counter` for frequency counting.
   - Using `.most_common(n)` for top-N ranking in $O(M \log k)$ time.
   - Status dictionary lookups for status name mappings.
3. **File Handling:**
   - Context managers (`with open(...) as f:`) ensuring clean descriptor closure.
   - Explicit UTF-8 encoding with fallback error replacement.
   - Line streaming iteration for minimal memory footprint.
4. **Data Modeling & Modular Design:**
   - Strong typing with `dataclasses` and type annotations (`typing.Dict`, `typing.Optional`, `typing.List`).
   - Single responsibility principle across parsing, analyzing, reporting, and CLI handling.
5. **CLI & System Integration:**
   - Full command-line argument parsing with `argparse`.
   - Standard output vs. standard error channel separation.
