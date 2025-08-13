# Rust Load Tester Implementation Status

This document outlines the current implementation status, features, and capabilities of the Rust-based high-performance load tester.

## Overview

The load tester is a command-line tool developed in Rust designed to generate high-throughput HTTP traffic for testing the performance and security of web applications and WAFs. It leverages asynchronous operations using `tokio` to achieve high concurrency and performance.

## Key Features

- **High Concurrency:** Utilizes `tokio`'s asynchronous runtime to handle thousands of concurrent connections efficiently.
- **Command-Line Interface:** A simple and clear CLI using `clap` allows users to configure:
    - `target_url`: The base URL of the target application.
    - `duration`: The total duration of the test in seconds.
    - `concurrency`: The number of concurrent clients (workers) to simulate.
- **Diverse Attack Simulation:**
    - Injects a variety of payloads to simulate common web attacks.
    - Pre-defined attack patterns include:
        - SQL Injection (SQLi)
        - Cross-Site Scripting (XSS)
        - Command Injection
        - Path Traversal
        - Local/Remote File Inclusion (LFI/RFI)
        - XML External Entity (XXE)
    - Randomly selects attack types and payloads for each request to ensure varied traffic.
- **Realistic Traffic Generation:**
    - Spoofs the `X-Forwarded-For` HTTP header with a randomized IP address for each request to simulate traffic from different sources.
    - Sets a custom `User-Agent` string (`SafeLine-Rust-LoadTester/1.0`).
- **Real-time Monitoring & Statistics:**
    - Provides a live console output every second, displaying key metrics:
        - **TPS (Transactions Per Second):** Current request rate.
        - **Total Requests:** Cumulative count of requests sent.
        - **Blocked Requests:** Number of requests identified as blocked by the WAF.
        - **Detection Rate:** Percentage of malicious requests successfully blocked.
        - **P99 Latency:** 99th percentile response time in milliseconds.
- **WAF Block Detection:**
    - Implements a `is_blocked` function to intelligently determine if a request was blocked.
    - Detection is based on:
        - HTTP status codes (e.g., `4xx` client errors).
        - Keywords in the response body (e.g., "blocked", "denied", "safeline", "forbidden").
- **Comprehensive Final Reporting:**
    - At the conclusion of the test, a detailed summary report is printed to the console, including:
        - Total test duration.
        - Aggregate counts for total, successful, and blocked requests.
        - Overall WAF detection rate.
        - Average Requests Per Second (RPS).
        - Latency statistics (Avg, Min, Max, p50, p90, p95, p99) calculated using `hdrhistogram`.
- **Data Export:**
    - Saves the raw data for all requests to a timestamped JSON file (e.g., `rust_load_test_results_YYYYMMDD_HHMMSS.json`) in the `test_results/` directory.
    - This allows for more detailed offline analysis.
- **Graceful Shutdown:** The application can be stopped gracefully at any time using `Ctrl+C`, ensuring that the final report is still generated with the data collected up to that point.

## Current Status

The implementation is **complete** and **functional**. It meets all the core requirements for a high-performance load testing tool with integrated security attack simulation. The code is well-structured, leveraging modern Rust idioms for asynchronous programming and concurrency.
